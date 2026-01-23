#!/bin/bash

#
# ChatAFL-Enhanced 验证测试脚本
# 用于验证 ChatAFL-Enhanced 的编译和配置是否正确
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHATAFL_ENHANCED_DIR="${SCRIPT_DIR}/ChatAFL-Enhanced"

echo "================================================"
echo "ChatAFL-Enhanced 验证测试"
echo "================================================"
echo

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

# 测试函数
test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((pass_count++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((fail_count++))
}

test_info() {
    echo -e "${YELLOW}ℹ INFO${NC}: $1"
}

# 测试1: 检查源文件是否存在
echo "测试 1: 检查 ChatAFL-Enhanced 源文件..."
if [ -f "${CHATAFL_ENHANCED_DIR}/verifier.c" ] && \
   [ -f "${CHATAFL_ENHANCED_DIR}/cegar-refinement.c" ] && \
   [ -f "${CHATAFL_ENHANCED_DIR}/state-scheduler.c" ]; then
    test_pass "所有增强模块源文件存在"
else
    test_fail "缺少增强模块源文件"
    test_info "请确保以下文件存在: verifier.c, cegar-refinement.c, state-scheduler.c"
fi

# 测试2: 编译基础模式
echo
echo "测试 2: 编译基础模式（不启用增强功能）..."
cd "${CHATAFL_ENHANCED_DIR}"
if make clean all > /tmp/chatafl_basic_build.log 2>&1; then
    test_pass "基础模式编译成功"
    if [ -f "afl-fuzz" ]; then
        test_pass "afl-fuzz 二进制生成成功"
    else
        test_fail "afl-fuzz 二进制未生成"
    fi
else
    test_fail "基础模式编译失败"
    test_info "查看日志: /tmp/chatafl_basic_build.log"
fi

# 测试3: 编译增强模式
echo
echo "测试 3: 编译增强模式（启用 CHATAFL_ENHANCED=1）..."
cd "${CHATAFL_ENHANCED_DIR}"
if make clean all CHATAFL_ENHANCED=1 > /tmp/chatafl_enhanced_build.log 2>&1; then
    test_pass "增强模式编译成功"
    
    # 检查是否链接了增强模块
    if nm afl-fuzz 2>/dev/null | grep -q "verifier_"; then
        test_pass "验证模块已链接到 afl-fuzz"
    else
        test_fail "验证模块未链接到 afl-fuzz"
    fi
else
    test_fail "增强模式编译失败"
    test_info "查看日志: /tmp/chatafl_enhanced_build.log"
fi

# 测试4: 检查 Makefile 条件编译
echo
echo "测试 4: 检查 Makefile 条件编译逻辑..."
if grep -q "ifdef CHATAFL_ENHANCED" "${CHATAFL_ENHANCED_DIR}/Makefile"; then
    test_pass "Makefile 包含条件编译逻辑"
else
    test_fail "Makefile 缺少条件编译逻辑"
fi

# 测试5: 检查 profuzzbench_exec_all.sh 脚本
echo
echo "测试 5: 检查 profuzzbench_exec_all.sh 是否支持 chatafl-enhanced..."
EXEC_SCRIPT="${SCRIPT_DIR}/benchmark/scripts/execution/profuzzbench_exec_all.sh"
if grep -q "chatafl-enhanced" "${EXEC_SCRIPT}"; then
    test_pass "执行脚本支持 chatafl-enhanced"
    
    # 统计支持的目标数量
    target_count=$(grep -c 'chatafl-enhanced' "${EXEC_SCRIPT}" || true)
    test_info "找到 ${target_count} 处 chatafl-enhanced 引用"
else
    test_fail "执行脚本不支持 chatafl-enhanced"
fi

# 测试6: 检查 Dockerfile 配置
echo
echo "测试 6: 检查 Dockerfile 是否配置了 chatafl-enhanced..."
dockerfile_count=0
for dockerfile in "${SCRIPT_DIR}"/benchmark/subjects/*/*/Dockerfile; do
    if [ -f "$dockerfile" ]; then
        if grep -q "chatafl-enhanced" "$dockerfile"; then
            ((dockerfile_count++))
        fi
    fi
done

if [ $dockerfile_count -gt 0 ]; then
    test_pass "找到 ${dockerfile_count} 个 Dockerfile 支持 chatafl-enhanced"
else
    test_fail "没有 Dockerfile 支持 chatafl-enhanced"
fi

# 测试7: 验证 run.sh 脚本
echo
echo "测试 7: 检查主 run.sh 脚本..."
RUN_SCRIPT="${SCRIPT_DIR}/run.sh"
if [ -f "${RUN_SCRIPT}" ] && [ -x "${RUN_SCRIPT}" ]; then
    test_pass "run.sh 脚本存在且可执行"
else
    test_fail "run.sh 脚本不存在或不可执行"
fi

# 测试8: 检查文档
echo
echo "测试 8: 检查增强功能文档..."
if [ -f "${CHATAFL_ENHANCED_DIR}/README-ENHANCED.md" ]; then
    test_pass "README-ENHANCED.md 文档存在"
else
    test_fail "README-ENHANCED.md 文档不存在"
fi

# 总结
echo
echo "================================================"
echo "测试总结"
echo "================================================"
echo -e "${GREEN}通过: ${pass_count}${NC}"
echo -e "${RED}失败: ${fail_count}${NC}"
echo

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ 所有测试通过！ChatAFL-Enhanced 配置正确。${NC}"
    echo
    echo "您现在可以使用以下命令运行模糊测试："
    echo "  ./run.sh 5 10 kamailio chatafl-enhanced"
    echo
    exit 0
else
    echo -e "${RED}✗ 有 ${fail_count} 个测试失败。请检查上述错误信息。${NC}"
    echo
    exit 1
fi
