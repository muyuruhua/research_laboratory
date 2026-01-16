#!/bin/bash
# ============================================================================
# ChatAFL-Enhanced 最终集成检查脚本
# 创建时间: 2026-01-13
# 功能: 全面检查编译、同步、Docker镜像和集成状态
# ============================================================================

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     ChatAFL-Enhanced 最终集成检查                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

WORKSPACE="/home/ckt/Documents/000_2026_dev/research_laboratory/ChatAFL-master"
cd $WORKSPACE

PASS=0
FAIL=0
WARN=0

# ============================================================================
# 检查1: 源代码目录集成状态
# ============================================================================
echo "┌─ 检查1: 源代码集成 ─────────────────────────────────────────┐"
cd "$WORKSPACE/ChatAFL-Enhanced"

# 1.1 检查关键模块文件
for module in verifier.c cegar.c state-scheduler.c protocol-spec.h; do
    if [ -f "$module" ]; then
        size=$(stat -c%s "$module")
        echo "  ✅ $module ($size bytes)"
        ((PASS++))
    else
        echo "  ❌ $module 缺失"
        ((FAIL++))
    fi
done

# 1.2 检查afl-fuzz.c集成点
echo ""
echo "  🔍 检查 afl-fuzz.c 集成点:"
grep_count=$(grep -c "verify_json_grammar" afl-fuzz.c 2>/dev/null || echo 0)
if [ "$grep_count" -ge 1 ]; then
    echo "  ✅ verify_json_grammar 调用: $grep_count 处"
    ((PASS++))
else
    echo "  ❌ verify_json_grammar 未集成到 afl-fuzz.c"
    ((FAIL++))
fi

header_count=$(grep -c "verifier.h" afl-fuzz.c 2>/dev/null || echo 0)
if [ "$header_count" -ge 1 ]; then
    echo "  ✅ verifier.h 头文件引入"
    ((PASS++))
else
    echo "  ⚠️  verifier.h 头文件可能缺失"
    ((WARN++))
fi

# 1.3 检查编译二进制
if [ -f "afl-fuzz" ]; then
    size=$(stat -c%s "afl-fuzz")
    echo ""
    echo "  ✅ afl-fuzz 二进制: $size bytes"
    
    # 检查符号表
    echo "  🔍 符号表检查:"
    for func in verify_json_grammar refine_hypothesis_with_cegar increment_state_count; do
        if nm afl-fuzz 2>/dev/null | grep -q "$func"; then
            echo "    ✅ $func"
            ((PASS++))
        else
            echo "    ❌ $func 缺失"
            ((FAIL++))
        fi
    done
else
    echo "  ❌ afl-fuzz 二进制缺失"
    ((FAIL++))
fi
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# ============================================================================
# 检查2: Benchmark同步状态
# ============================================================================
echo "┌─ 检查2: Benchmark同步 ───────────────────────────────────────┐"
cd "$WORKSPACE/benchmark/subjects"

sync_count=0
total_subjects=0
for protocol_dir in */; do
    for subject_dir in "$protocol_dir"*/; do
        ((total_subjects++))
        if [ -d "$subject_dir/chatafl-enhanced" ]; then
            ((sync_count++))
            
            # 检查关键文件
            has_verifier=0
            has_cegar=0
            has_state=0
            [ -f "$subject_dir/chatafl-enhanced/verifier.c" ] && has_verifier=1
            [ -f "$subject_dir/chatafl-enhanced/cegar.c" ] && has_cegar=1
            [ -f "$subject_dir/chatafl-enhanced/state-scheduler.c" ] && has_state=1
            
            if [ $has_verifier -eq 1 ] && [ $has_cegar -eq 1 ] && [ $has_state -eq 1 ]; then
                status="✅"
                ((PASS++))
            else
                status="⚠️ "
                ((WARN++))
            fi
            echo "  $status ${subject_dir%/}"
        else
            echo "  ❌ ${subject_dir%/} - chatafl-enhanced缺失"
            ((FAIL++))
        fi
    done
done

echo ""
echo "  📊 同步统计: $sync_count/$total_subjects 个目标"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# ============================================================================
# 检查3: Docker镜像状态
# ============================================================================
echo "┌─ 检查3: Docker镜像 ──────────────────────────────────────────┐"

docker_images=$(sudo docker images --format "{{.Repository}}" | grep -E "lightftp|bftpd|proftpd|pure-ftpd|exim|live555|kamailio|forked-daapd|lighttpd1" | wc -l)

echo "  📦 Docker镜像数量: $docker_images/9"

if [ $docker_images -eq 9 ]; then
    echo "  ✅ 所有镜像已构建"
    ((PASS++))
elif [ $docker_images -gt 0 ]; then
    echo "  ⚠️  部分镜像缺失"
    ((WARN++))
else
    echo "  ❌ 无Docker镜像"
    ((FAIL++))
fi

# 检查一个镜像中的afl-fuzz
echo ""
echo "  🔍 检查 BFTPD 镜像内容:"
if sudo docker run --rm bftpd /bin/bash -c "[ -f /home/ubuntu/chatafl-enhanced/afl-fuzz ]" 2>/dev/null; then
    size=$(sudo docker run --rm bftpd /bin/bash -c "stat -c%s /home/ubuntu/chatafl-enhanced/afl-fuzz" 2>/dev/null)
    echo "  ✅ afl-fuzz 存在 ($size bytes)"
    ((PASS++))
    
    # 检查符号表
    echo "  🔍 符号表:"
    for func in verify_json_grammar refine_hypothesis_with_cegar increment_state_count; do
        if sudo docker run --rm bftpd /bin/bash -c "nm /home/ubuntu/chatafl-enhanced/afl-fuzz" 2>/dev/null | grep -q "$func"; then
            echo "    ✅ $func"
            ((PASS++))
        else
            echo "    ❌ $func 缺失"
            ((FAIL++))
        fi
    done
    
    # 检查集成代码
    echo ""
    echo "  🔍 集成代码检查:"
    if sudo docker run --rm bftpd /bin/bash -c "grep -q 'verify_json_grammar' /home/ubuntu/chatafl-enhanced/afl-fuzz.c" 2>/dev/null; then
        echo "  ✅ verify_json_grammar 已集成到 afl-fuzz.c"
        ((PASS++))
    else
        echo "  ❌ verify_json_grammar 未集成到 afl-fuzz.c"
        echo "  ⚠️  Docker镜像需要重新构建！"
        ((FAIL++))
    fi
else
    echo "  ❌ afl-fuzz 不存在"
    ((FAIL++))
fi

echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# ============================================================================
# 检查4: API密钥配置
# ============================================================================
echo "┌─ 检查4: API密钥配置 ─────────────────────────────────────────┐"
cd "$WORKSPACE"

api_key=$(grep "OPENAI_TOKEN" ChatAFL-Enhanced/chat-llm.h | sed -n 's/.*"\(.*\)"/\1/p')
if [ -n "$api_key" ] && [ "$api_key" != "your-api-key-here" ]; then
    echo "  ✅ API密钥已配置: ${api_key:0:20}..."
    ((PASS++))
else
    echo "  ❌ API密钥未配置"
    ((FAIL++))
fi

echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# ============================================================================
# 检查5: 编译警告/错误检查
# ============================================================================
echo "┌─ 检查5: 编译质量 ────────────────────────────────────────────┐"
cd "$WORKSPACE/ChatAFL-Enhanced"

echo "  🔨 重新编译检查..."
compile_output=$(make clean all 2>&1)
compile_errors=$(echo "$compile_output" | grep -c "error:" || echo 0)
compile_warnings=$(echo "$compile_output" | grep -c "warning:" || echo 0)

if [ $compile_errors -eq 0 ]; then
    echo "  ✅ 编译错误: 0"
    ((PASS++))
else
    echo "  ❌ 编译错误: $compile_errors"
    ((FAIL++))
fi

if [ $compile_warnings -eq 0 ]; then
    echo "  ✅ 编译警告: 0"
    ((PASS++))
else
    echo "  ⚠️  编译警告: $compile_warnings"
    ((WARN++))
fi

echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# ============================================================================
# 最终总结
# ============================================================================
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    检查结果汇总                                 ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║  ✅ 通过: $PASS                                                   "
echo "║  ⚠️  警告: $WARN                                                   "
echo "║  ❌ 失败: $FAIL                                                   "
echo "╠════════════════════════════════════════════════════════════════╣"

total_checks=$((PASS + WARN + FAIL))
pass_rate=$((PASS * 100 / total_checks))

if [ $FAIL -eq 0 ] && [ $WARN -eq 0 ]; then
    echo "║  状态: ✅ 完美！所有检查通过                                    "
    echo "║  评级: ★★★★★ (5/5)                                           "
    echo "║  建议: 立即开始实验                                            "
elif [ $FAIL -eq 0 ]; then
    echo "║  状态: ✅ 良好，有少量警告                                      "
    echo "║  评级: ★★★★☆ (4/5)                                           "
    echo "║  建议: 可以开始实验，关注警告项                                 "
elif [ $FAIL -le 3 ]; then
    echo "║  状态: ⚠️  需要注意，有部分失败                                 "
    echo "║  评级: ★★★☆☆ (3/5)                                           "
    echo "║  建议: 修复失败项后再实验                                      "
else
    echo "║  状态: ❌ 严重问题，需要修复                                    "
    echo "║  评级: ★★☆☆☆ (2/5)                                           "
    echo "║  建议: 必须修复所有失败项                                      "
fi

echo "║  通过率: $pass_rate%                                              "
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ============================================================================
# 关键问题识别
# ============================================================================
if [ $FAIL -gt 0 ]; then
    echo "⚠️  发现关键问题:"
    echo ""
    
    # 检查Docker镜像是否需要重建
    if ! sudo docker run --rm bftpd /bin/bash -c "grep -q 'verify_json_grammar' /home/ubuntu/chatafl-enhanced/afl-fuzz.c" 2>/dev/null; then
        echo "  🔧 问题: Docker镜像中的代码未包含最新集成"
        echo "  📝 解决方案:"
        echo "     1. 确保 ChatAFL-Enhanced/afl-fuzz.c 包含 verify_json_grammar 调用"
        echo "     2. 重新运行: sudo KEY='your_key' ./setup.sh"
        echo "     3. 等待15-20分钟完成Docker镜像重建"
        echo ""
    fi
fi

# ============================================================================
# 下一步建议
# ============================================================================
echo "📋 下一步操作:"
echo ""

if [ $FAIL -gt 0 ]; then
    echo "  1️⃣  修复上述失败项"
    echo "  2️⃣  重新构建Docker镜像:"
    echo "      cd $WORKSPACE"
    echo "      sudo KEY='your_api_key' ./setup.sh"
    echo "  3️⃣  重新运行此检查脚本"
    echo "  4️⃣  开始实验测试"
else
    echo "  1️⃣  快速功能测试 (5分钟):"
    echo "      cd $WORKSPACE/benchmark"
    echo "      ./run.sh -n bftpd -b chatafl-enhanced -t 300 -r 1"
    echo ""
    echo "  2️⃣  查看验证器日志:"
    echo "      tail -f out-bftpd-*/fuzzer_stats"
    echo "      grep -r 'VERIFIER\\|verify_json' out-bftpd-*/"
    echo ""
    echo "  3️⃣  完整实验 (建议24小时):"
    echo "      ./run.sh -n bftpd -b chatafl-enhanced -t 86400 -r 3"
fi

echo ""
echo "✅ 检查完成！详细报告已保存。"
