#!/bin/bash
# ============================================================================
# ChatAFL-Enhanced Docker镜像重建脚本
# 目的: 重新构建包含最新集成代码的Docker镜像
# 时间: 预计15-20分钟
# ============================================================================

set -e  # 遇到错误立即退出

WORKSPACE="/home/ckt/Documents/000_2026_dev/research_laboratory/ChatAFL-master"
cd $WORKSPACE

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     ChatAFL-Enhanced Docker镜像重建                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# 检查API密钥
API_KEY=${KEY:-$(grep "OPENAI_TOKEN" ChatAFL-Enhanced/chat-llm.h | sed -n 's/.*"\(.*\)"/\1/p')}
if [ -z "$API_KEY" ] || [ "$API_KEY" = "your-api-key-here" ]; then
    echo "❌ 错误: 未设置API密钥"
    echo "请使用: sudo KEY='your_openai_key' ./rebuild-docker.sh"
    exit 1
fi

echo "✅ API密钥: ${API_KEY:0:20}..."
echo ""

# ============================================================================
# 步骤1: 验证源代码集成
# ============================================================================
echo "📋 步骤1: 验证源代码集成..."

cd ChatAFL-Enhanced
if grep -q "verify_json_grammar" afl-fuzz.c; then
    echo "  ✅ afl-fuzz.c 包含 verify_json_grammar 调用"
else
    echo "  ❌ 错误: afl-fuzz.c 缺少 verify_json_grammar 调用"
    echo "  请先运行集成脚本！"
    exit 1
fi

if [ -f "verifier.c" ] && [ -f "cegar.c" ] && [ -f "state-scheduler.c" ]; then
    echo "  ✅ 所有新模块文件存在"
else
    echo "  ❌ 错误: 新模块文件缺失"
    exit 1
fi

cd ..

# ============================================================================
# 步骤2: 更新API密钥
# ============================================================================
echo ""
echo "📋 步骤2: 更新API密钥..."

for version in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced; do
    sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$API_KEY\"/" $version/chat-llm.h
    echo "  ✅ $version/chat-llm.h 已更新"
done

# ============================================================================
# 步骤3: 同步到Benchmark目录
# ============================================================================
echo ""
echo "📋 步骤3: 同步代码到Benchmark..."

sync_count=0
for subject in ./benchmark/subjects/*/*; do
    # 备份旧版本
    if [ -d "$subject/chatafl-enhanced" ]; then
        rm -rf "$subject/chatafl-enhanced.backup" 2>/dev/null || true
        cp -r "$subject/chatafl-enhanced" "$subject/chatafl-enhanced.backup" 2>/dev/null || true
    fi
    
    # 同步新版本
    rm -rf "$subject/chatafl-enhanced" 2>/dev/null || true
    cp -r ChatAFL-Enhanced "$subject/chatafl-enhanced"
    
    # 同步其他版本
    rm -rf "$subject/aflnet" 2>/dev/null || true
    cp -r aflnet "$subject/aflnet"
    
    rm -rf "$subject/chatafl" 2>/dev/null || true
    cp -r ChatAFL "$subject/chatafl"
    
    rm -rf "$subject/chatafl-cl1" 2>/dev/null || true
    cp -r ChatAFL-CL1 "$subject/chatafl-cl1"
    
    rm -rf "$subject/chatafl-cl2" 2>/dev/null || true
    cp -r ChatAFL-CL2 "$subject/chatafl-cl2"
    
    ((sync_count++))
done

echo "  ✅ 已同步 $sync_count 个目标目录"

# ============================================================================
# 步骤4: 构建Docker镜像
# ============================================================================
echo ""
echo "📋 步骤4: 构建Docker镜像 (这将需要15-20分钟)..."
echo ""

PFBENCH="$PWD/benchmark"
cd $PFBENCH

# 定义镜像列表
declare -a targets=(
    "subjects/FTP/LightFTP:lightftp"
    "subjects/FTP/BFTPD:bftpd"
    "subjects/FTP/ProFTPD:proftpd"
    "subjects/FTP/PureFTPD:pure-ftpd"
    "subjects/SMTP/Exim:exim"
    "subjects/RTSP/Live555:live555"
    "subjects/SIP/Kamailio:kamailio"
    "subjects/DAAP/forked-daapd:forked-daapd"
    "subjects/HTTP/Lighttpd1:lighttpd1"
)

build_success=0
build_fail=0

for target in "${targets[@]}"; do
    IFS=':' read -r dir name <<< "$target"
    
    echo ""
    echo "🔨 构建 $name..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    cd "$PFBENCH/$dir"
    
    if sudo docker build . -t "$name" --build-arg MAKE_OPT 2>&1 | tee "/tmp/build_${name}.log"; then
        echo "  ✅ $name 构建成功"
        ((build_success++))
    else
        echo "  ❌ $name 构建失败"
        ((build_fail++))
    fi
    
    cd "$PFBENCH"
done

# ============================================================================
# 步骤5: 验证构建结果
# ============================================================================
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                   构建结果验证                                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# 验证一个镜像
echo "🔍 验证 BFTPD 镜像..."
if sudo docker run --rm bftpd /bin/bash -c "grep -q 'verify_json_grammar' /home/ubuntu/chatafl-enhanced/afl-fuzz.c" 2>/dev/null; then
    echo "  ✅ verify_json_grammar 已集成到 Docker 镜像"
    
    # 检查符号表
    if sudo docker run --rm bftpd /bin/bash -c "nm /home/ubuntu/chatafl-enhanced/afl-fuzz" 2>/dev/null | grep -q "verify_json_grammar"; then
        echo "  ✅ 符号表包含 verify_json_grammar"
    else
        echo "  ⚠️  符号表可能有问题"
    fi
else
    echo "  ❌ verify_json_grammar 未集成"
    echo "  ⚠️  可能需要重新检查源代码"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                      最终统计                                   ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║  构建成功: $build_success/9                                         "
echo "║  构建失败: $build_fail/9                                            "

if [ $build_fail -eq 0 ]; then
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║  状态: ✅ 所有镜像构建成功！                                    "
    echo "║  评级: ★★★★★ (5/5)                                           "
    echo "║  建议: 可以开始实验了！                                        "
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📋 快速测试命令:"
    echo "   cd $PFBENCH"
    echo "   ./run.sh -n bftpd -b chatafl-enhanced -t 300 -r 1"
else
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║  状态: ⚠️  部分镜像构建失败                                     "
    echo "║  建议: 查看日志文件 /tmp/build_*.log                           "
    echo "╚════════════════════════════════════════════════════════════════╝"
fi

echo ""
echo "✅ 重建完成！"
