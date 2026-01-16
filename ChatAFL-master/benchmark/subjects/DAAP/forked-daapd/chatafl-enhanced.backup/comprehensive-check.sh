#!/bin/bash
# 全面检查ChatAFL-Enhanced集成状态

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ChatAFL-Enhanced 集成完整性检查报告                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# 1. 文件完整性检查
echo "┌─ 1/7 文件完整性 ────────────────────────────────────────┐"
FILES=("verifier.c" "verifier.h" "cegar.c" "cegar.h" "state-scheduler.c" "state-scheduler.h" "protocol-spec.h")
for f in "${FILES[@]}"; do
    if [ -f "$f" ]; then
        lines=$(wc -l < "$f")
        printf "  ✓ %-25s %5d lines\n" "$f" "$lines"
    else
        printf "  ✗ %-25s MISSING\n" "$f"
    fi
done
echo ""

# 2. 编译状态
echo "┌─ 2/7 编译状态 ──────────────────────────────────────────┐"
if [ -f "afl-fuzz" ]; then
    SIZE=$(stat -c%s afl-fuzz | numfmt --to=iec-i)
    TIMESTAMP=$(stat -c%y afl-fuzz | cut -d' ' -f1,2 | cut -d'.' -f1)
    echo "  ✓ afl-fuzz: $SIZE ($TIMESTAMP)"
else
    echo "  ✗ afl-fuzz: NOT COMPILED"
fi

# 检查.o文件
for obj in verifier.o cegar.o state-scheduler.o chat-llm.o aflnet.o; do
    if [ -f "$obj" ]; then
        echo "  ✓ $obj"
    else
        echo "  ✗ $obj: MISSING"
    fi
done
echo ""

# 3. 符号表检查
echo "┌─ 3/7 符号表检查 ────────────────────────────────────────┐"
if [ -f "afl-fuzz" ]; then
    FUNCS=("verify_json_grammar" "extract_protocol_state" "refine_hypothesis_with_cegar" 
           "minimize_counterexample" "increment_state_count" "pick_least_visited_state" "is_plateau")
    for func in "${FUNCS[@]}"; do
        if nm afl-fuzz 2>/dev/null | grep -q "$func"; then
            echo "  ✓ $func"
        else
            echo "  ✗ $func: NOT LINKED"
        fi
    done
else
    echo "  ✗ Cannot check symbols (afl-fuzz not found)"
fi
echo ""

# 4. 源码集成检查
echo "┌─ 4/7 源码集成检查 ──────────────────────────────────────┐"
if grep -q "ChatAFL-Enhanced: 验证器计数器" afl-fuzz.c; then
    echo "  ✓ fuzz_one() 变量声明"
else
    echo "  ✗ fuzz_one() 变量声明: MISSING"
fi

if grep -q "verify_json_grammar((char\*)out_buf" afl-fuzz.c; then
    CALL_COUNT=$(grep -c "verify_json_grammar" afl-fuzz.c)
    echo "  ✓ verify_json_grammar() 调用 ($CALL_COUNT 处)"
else
    echo "  ✗ verify_json_grammar() 调用: MISSING"
fi

if grep -q "setup_protocol_spec()" afl-fuzz.c; then
    echo "  ✓ setup_protocol_spec() 初始化"
else
    echo "  ✗ setup_protocol_spec() 初始化: MISSING"
fi

if grep -q "g_protocol_spec" afl-fuzz.c; then
    echo "  ✓ 全局变量声明"
else
    echo "  ✗ 全局变量声明: MISSING"
fi
echo ""

# 5. 编译警告分析
echo "┌─ 5/7 编译警告分析 ──────────────────────────────────────┐"
make clean >/dev/null 2>&1
WARNINGS=$(make afl-fuzz 2>&1 | grep -c "warning:")
ERRORS=$(make afl-fuzz 2>&1 | grep -c "error:")
echo "  编译警告: $WARNINGS"
echo "  编译错误: $ERRORS"

if [ "$ERRORS" -eq 0 ]; then
    echo "  ✓ 编译成功 (无致命错误)"
else
    echo "  ✗ 编译失败 ($ERRORS 个错误)"
fi
echo ""

# 6. 未使用变量分析
echo "┌─ 6/7 未使用变量 ────────────────────────────────────────┐"
UNUSED_VARS=$(make afl-fuzz 2>&1 | grep "defined but not used" | wc -l)
if [ "$UNUSED_VARS" -gt 0 ]; then
    echo "  ⚠ $UNUSED_VARS 个未使用的变量 (Phase 2将使用)"
    make afl-fuzz 2>&1 | grep "defined but not used" | sed 's/.*'\''//g' | sed 's/'\''.*//g' | while read var; do
        echo "    - $var"
    done
else
    echo "  ✓ 无未使用变量"
fi
echo ""

# 7. 集成覆盖率
echo "┌─ 7/7 集成覆盖率 ────────────────────────────────────────┐"
TOTAL_MODULES=3
INTEGRATED_MODULES=0

if grep -q "verify_json_grammar" afl-fuzz.c; then
    echo "  ✓ Verifier (verifier.c) - 已集成"
    ((INTEGRATED_MODULES++))
else
    echo "  ✗ Verifier (verifier.c) - 未集成"
fi

if grep -q "refine_hypothesis_with_cegar" afl-fuzz.c; then
    echo "  ✓ CEGAR (cegar.c) - 已集成"
    ((INTEGRATED_MODULES++))
else
    echo "  ⚠ CEGAR (cegar.c) - 待Phase 2"
fi

if grep -q "increment_state_count.*pick_least_visited_state" afl-fuzz.c; then
    echo "  ✓ State Scheduler (state-scheduler.c) - 已集成"
    ((INTEGRATED_MODULES++))
else
    echo "  ⚠ State Scheduler (state-scheduler.c) - 待Phase 2"
fi

COVERAGE=$((INTEGRATED_MODULES * 100 / TOTAL_MODULES))
echo ""
echo "  集成进度: $INTEGRATED_MODULES/$TOTAL_MODULES 模块 ($COVERAGE%)"
echo ""

# 最终结论
echo "╔════════════════════════════════════════════════════════════╗"
if [ "$ERRORS" -eq 0 ] && [ "$INTEGRATED_MODULES" -ge 1 ]; then
    echo "║  ✅ 状态: MVP集成成功 (v1.0-minimal)                        ║"
    echo "║  📊 集成度: $COVERAGE%                                            ║"
    echo "║  🎯 下一步: Phase 2 完整集成                                ║"
else
    echo "║  ❌ 状态: 集成未完成                                        ║"
    echo "║  🔧 需要: 修复编译错误或完成基础集成                         ║"
fi
echo "╚════════════════════════════════════════════════════════════╝"
