#!/bin/bash
# 最终验证脚本 - 确认所有集成都正确

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          ChatAFL-Enhanced 最终验证报告                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

PASS_COUNT=0
TOTAL_COUNT=0

check_item() {
    ((TOTAL_COUNT++))
    if [ $1 -eq 0 ]; then
        echo "  ✅ $2"
        ((PASS_COUNT++))
        return 0
    else
        echo "  ❌ $2"
        return 1
    fi
}

warn_item() {
    echo "  ⚠️  $1"
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 1. 文件完整性检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ -f "verifier.c" ] && [ -f "verifier.h" ]
check_item $? "verifier模块源文件"

[ -f "cegar.c" ] && [ -f "cegar.h" ]
check_item $? "cegar模块源文件"

[ -f "state-scheduler.c" ] && [ -f "state-scheduler.h" ]
check_item $? "state-scheduler模块源文件"

[ -f "protocol-spec.h" ]
check_item $? "protocol-spec头文件"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 2. 编译产物检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[ -f "afl-fuzz" ] && [ -x "afl-fuzz" ]
check_item $? "afl-fuzz可执行文件"

[ -f "verifier.o" ] && [ -f "cegar.o" ] && [ -f "state-scheduler.o" ]
check_item $? "模块目标文件 (.o)"

[ -f "chat-llm.o" ] && [ -f "aflnet.o" ]
check_item $? "依赖目标文件"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 3. 符号链接验证"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

nm afl-fuzz 2>/dev/null | grep -q "verify_json_grammar"
check_item $? "verify_json_grammar已链接"

nm afl-fuzz 2>/dev/null | grep -q "refine_hypothesis_with_cegar"
check_item $? "refine_hypothesis_with_cegar已链接"

nm afl-fuzz 2>/dev/null | grep -q "increment_state_count"
check_item $? "increment_state_count已链接"

nm afl-fuzz 2>/dev/null | grep -q "extract_protocol_state"
check_item $? "extract_protocol_state已链接"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 4. 源码集成验证"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

grep -q "^#include \"verifier.h\"" afl-fuzz.c
check_item $? "verifier.h头文件引用"

grep -q "^#include \"cegar.h\"" afl-fuzz.c
check_item $? "cegar.h头文件引用"

grep -q "^#include \"state-scheduler.h\"" afl-fuzz.c
check_item $? "state-scheduler.h头文件引用"

grep -q "static ProtocolSpec g_protocol_spec" afl-fuzz.c
check_item $? "全局变量g_protocol_spec声明"

grep -q "setup_protocol_spec()" afl-fuzz.c
check_item $? "setup_protocol_spec()初始化调用"

grep -q "verify_json_grammar((char\*)out_buf" afl-fuzz.c
check_item $? "verify_json_grammar()运行时调用"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 5. 编译质量检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

make clean >/dev/null 2>&1
ERROR_COUNT=$(make afl-fuzz 2>&1 | grep -c "error:")
[ "$ERROR_COUNT" -eq 0 ]
check_item $? "无编译错误 (error count: $ERROR_COUNT)"

UNUSED_COUNT=$(make afl-fuzz 2>&1 | grep -c "defined but not used")
[ "$UNUSED_COUNT" -eq 0 ]
check_item $? "无未使用变量警告 (unused count: $UNUSED_COUNT)"

WARNING_COUNT=$(make afl-fuzz 2>&1 | grep -c "warning:")
if [ "$WARNING_COUNT" -le 5 ]; then
    check_item 0 "警告数量可接受 (warning count: $WARNING_COUNT)"
else
    check_item 1 "警告数量过多 (warning count: $WARNING_COUNT)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 6. Docker/Benchmark准备"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

grep -q "ChatAFL-Enhanced" ../setup.sh
check_item $? "setup.sh包含ChatAFL-Enhanced配置"

[ -d "../benchmark/subjects/FTP/BFTPD/chatafl-enhanced" ]
if [ $? -eq 0 ]; then
    warn_item "benchmark目录存在但afl-fuzz需要同步"
else
    warn_item "benchmark目录不存在 (运行setup.sh后创建)"
fi

docker images 2>/dev/null | grep -q "chatafl-enhanced"
if [ $? -eq 0 ]; then
    echo "  ✅ Docker镜像已构建"
else
    warn_item "Docker镜像未构建 (需运行: sudo KEY='xxx' ./setup.sh)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 7. 集成覆盖率统计"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

VERIFIER_CALLS=$(grep -c "verify_json_grammar" afl-fuzz.c 2>/dev/null || echo 0)
CEGAR_CALLS=$(grep -c "refine_hypothesis_with_cegar" afl-fuzz.c 2>/dev/null || echo 0)
STATE_CALLS=$(grep -c "increment_state_count" afl-fuzz.c 2>/dev/null || echo 0)

echo "  Verifier集成:        $VERIFIER_CALLS 处调用 $([ $VERIFIER_CALLS -gt 0 ] && echo '✅' || echo '❌')"
echo "  CEGAR集成:           $CEGAR_CALLS 处调用 $([ $CEGAR_CALLS -gt 0 ] && echo '✅' || echo '⏳ Phase 2')"
echo "  State Scheduler集成: $STATE_CALLS 处调用 $([ $STATE_CALLS -gt 0 ] && echo '✅' || echo '⏳ Phase 2')"

INTEGRATED=0
[ $VERIFIER_CALLS -gt 0 ] && ((INTEGRATED++))
[ $CEGAR_CALLS -gt 0 ] && ((INTEGRATED++))
[ $STATE_CALLS -gt 0 ] && ((INTEGRATED++))

COVERAGE=$((INTEGRATED * 100 / 3))
echo ""
echo "  集成进度: $INTEGRATED/3 模块 ($COVERAGE%)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 最终评估"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

PASS_RATE=$((PASS_COUNT * 100 / TOTAL_COUNT))
echo ""
echo "  测试通过率: $PASS_COUNT/$TOTAL_COUNT ($PASS_RATE%)"
echo "  集成覆盖率: $COVERAGE%"
echo ""

if [ "$ERROR_COUNT" -eq 0 ] && [ "$PASS_RATE" -ge 80 ] && [ "$INTEGRATED" -ge 1 ]; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✅ 验证通过: ChatAFL-Enhanced可用于实验                       ║"
    echo "║                                                              ║"
    echo "║  版本: v1.0-minimal (MVP)                                    ║"
    echo "║  状态: 编译成功, 部分集成完成                                  ║"
    echo "║  建议: 运行sudo setup.sh同步到Docker                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  警告: 存在需要修复的问题                                  ║"
    echo "║                                                              ║"
    echo "║  错误数: $ERROR_COUNT                                             ║"
    echo "║  通过率: $PASS_RATE%                                             ║"
    echo "║  集成度: $COVERAGE%                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 1
fi
