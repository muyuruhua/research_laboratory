#!/bin/bash
# 深度代码质量检查

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        ChatAFL-Enhanced 深度代码质量检查                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

ISSUES=0

# 1. 检查内存管理问题
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 1. 内存管理检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查malloc/free配对
MALLOC_COUNT=$(grep -r "malloc\|calloc\|strdup" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
FREE_COUNT=$(grep -r "free(" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
echo "  malloc/calloc/strdup: $MALLOC_COUNT 次"
echo "  free调用: $FREE_COUNT 次"
if [ $MALLOC_COUNT -gt $((FREE_COUNT + 5)) ]; then
    echo "  ⚠️  可能存在内存泄漏 (malloc >> free)"
    ((ISSUES++))
else
    echo "  ✓ 内存管理基本平衡"
fi

# 检查返回值是否被检查
UNCHECKED=$(grep -n "malloc\|calloc" verifier.c cegar.c state-scheduler.c 2>/dev/null | while read line; do
    LINENUM=$(echo $line | cut -d: -f2)
    NEXTLINE=$((LINENUM + 1))
    FILE=$(echo $line | cut -d: -f1)
    if ! sed -n "${NEXTLINE}p" "$FILE" 2>/dev/null | grep -q "if.*NULL"; then
        echo "$line"
    fi
done | wc -l)

if [ $UNCHECKED -gt 0 ]; then
    echo "  ⚠️  $UNCHECKED 处malloc未检查返回值"
    ((ISSUES++))
else
    echo "  ✓ 所有malloc都有NULL检查"
fi

echo ""

# 2. 缓冲区溢出检查
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 2. 缓冲区安全检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查危险函数
STRCPY_COUNT=$(grep -r "strcpy(" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
SPRINTF_COUNT=$(grep -r "sprintf(" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
STRCAT_COUNT=$(grep -r "strcat(" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)

echo "  危险函数使用:"
echo "    strcpy:  $STRCPY_COUNT 处"
echo "    sprintf: $SPRINTF_COUNT 处"
echo "    strcat:  $STRCAT_COUNT 处"

if [ $((STRCPY_COUNT + SPRINTF_COUNT + STRCAT_COUNT)) -gt 0 ]; then
    echo "  ⚠️  使用了不安全的字符串函数"
    ((ISSUES++))
else
    echo "  ✓ 未使用危险的字符串函数"
fi

# 检查安全函数使用
STRNCPY_COUNT=$(grep -r "strncpy\|strlcpy" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
SNPRINTF_COUNT=$(grep -r "snprintf" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
echo "  安全函数使用:"
echo "    strncpy/strlcpy: $STRNCPY_COUNT 处"
echo "    snprintf:        $SNPRINTF_COUNT 处"

echo ""

# 3. 空指针检查
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 3. 空指针安全检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查函数参数的NULL检查
FUNCS=$(grep -E "^[a-z_]+ [a-z_]+\(" verifier.c cegar.c state-scheduler.c 2>/dev/null | grep -v "^static" | wc -l)
echo "  公共函数数量: $FUNCS"

# 检查是否有足够的NULL检查
NULL_CHECKS=$(grep -r "if.*==.*NULL\|if.*!.*NULL\|if (!.*)" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
echo "  NULL检查数量: $NULL_CHECKS"

if [ $NULL_CHECKS -lt 5 ]; then
    echo "  ⚠️  NULL检查可能不足"
    ((ISSUES++))
else
    echo "  ✓ 有充足的NULL检查"
fi

echo ""

# 4. JSON解析错误处理
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 4. JSON解析错误处理"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

JSON_PARSE=$(grep -r "json_tokener_parse\|json_object" verifier.c cegar.c 2>/dev/null | wc -l)
JSON_ERROR_HANDLE=$(grep -r "json.*==.*NULL\|is_error" verifier.c cegar.c 2>/dev/null | wc -l)

echo "  JSON解析调用: $JSON_PARSE 次"
echo "  错误处理: $JSON_ERROR_HANDLE 次"

if [ $JSON_PARSE -gt 0 ] && [ $JSON_ERROR_HANDLE -lt $((JSON_PARSE / 2)) ]; then
    echo "  ⚠️  JSON解析错误处理不足"
    ((ISSUES++))
else
    echo "  ✓ JSON错误处理充分"
fi

echo ""

# 5. 线程安全检查
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 5. 线程安全检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

STATIC_VARS=$(grep -r "^static.*=" verifier.c cegar.c state-scheduler.c 2>/dev/null | grep -v "const" | wc -l)
echo "  静态可变变量: $STATIC_VARS 个"

if [ $STATIC_VARS -gt 3 ]; then
    echo "  ⚠️  可能存在线程安全问题（多个静态变量）"
    echo "     注意: AFL是单线程，但LLM调用可能异步"
    ((ISSUES++))
else
    echo "  ✓ 静态变量数量合理"
fi

echo ""

# 6. AFL集成兼容性检查
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 6. AFL/AFLNet兼容性检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查是否使用了AFL的宏
AFL_MACROS=$(grep -r "ACTF\|SAYF\|WARNF\|FATAL" afl-fuzz.c 2>/dev/null | grep "ChatAFL-Enhanced\|VERIFIER\|CEGAR" | wc -l)
echo "  使用AFL日志宏: $AFL_MACROS 处"

if [ $AFL_MACROS -gt 0 ]; then
    echo "  ✓ 正确使用AFL的日志系统"
else
    echo "  ⚠️  未使用AFL日志宏（可能影响调试）"
fi

# 检查是否修改了关键AFL变量
CRITICAL_VARS=$(grep -E "queued_paths|unique_crashes|trace_bits" verifier.c cegar.c state-scheduler.c 2>/dev/null | grep -v "//" | wc -l)
if [ $CRITICAL_VARS -gt 0 ]; then
    echo "  ⚠️  直接修改了AFL关键变量（危险）"
    ((ISSUES++))
else
    echo "  ✓ 未直接修改AFL关键变量"
fi

echo ""

# 7. 性能影响评估
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 7. 性能影响评估"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查循环复杂度
LOOPS=$(grep -r "for\|while" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
NESTED=$(grep -A10 "for\|while" verifier.c cegar.c state-scheduler.c 2>/dev/null | grep "for\|while" | wc -l)
echo "  循环数量: $LOOPS"
echo "  嵌套循环: $((NESTED - LOOPS))"

# 检查是否在fuzz_one中有昂贵操作
VERIFY_IN_LOOP=$(grep -A5 -B5 "verify_json_grammar" afl-fuzz.c 2>/dev/null | grep "for\|while" | wc -l)
if [ $VERIFY_IN_LOOP -gt 0 ]; then
    echo "  ⚠️  验证器在紧密循环中调用（性能影响）"
    echo "     建议: 采样调用（当前是每50次1次）"
fi

# 检查采样率设置
SAMPLE_RATE=$(grep "verifier_check_interval" afl-fuzz.c 2>/dev/null | grep -o "[0-9]\+" | head -1)
if [ -n "$SAMPLE_RATE" ]; then
    echo "  ✓ 采样率: 1/$SAMPLE_RATE ($(echo "scale=2; 100/$SAMPLE_RATE" | bc)%)"
else
    echo "  ⚠️  未找到采样率配置"
fi

echo ""

# 8. 编译器优化检查
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 8. 编译器优化检查"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查是否有未优化的代码
INLINE_FUNCS=$(grep -r "inline" verifier.h cegar.h state-scheduler.h 2>/dev/null | wc -l)
echo "  inline函数: $INLINE_FUNCS 个"

if [ $INLINE_FUNCS -eq 0 ]; then
    echo "  ℹ️  未使用inline优化（小函数可考虑）"
else
    echo "  ✓ 有使用inline优化"
fi

echo ""

# 9. 错误消息和调试信息
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 9. 错误消息和调试支持"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

ERROR_MSGS=$(grep -r "fprintf\|printf\|ACTF\|WARNF" verifier.c cegar.c state-scheduler.c 2>/dev/null | wc -l)
echo "  错误/调试消息: $ERROR_MSGS 处"

if [ $ERROR_MSGS -lt 3 ]; then
    echo "  ⚠️  调试信息可能不足"
else
    echo "  ✓ 有充足的调试信息"
fi

echo ""

# 最终报告
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " 检查总结"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  发现的潜在问题: $ISSUES 个"
echo ""

if [ $ISSUES -eq 0 ]; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ✅ 代码质量检查通过                                          ║"
    echo "║     未发现严重问题                                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 0
elif [ $ISSUES -le 3 ]; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  发现少量问题                                             ║"
    echo "║     建议审查但不影响基本功能                                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ❌ 发现多个问题                                              ║"
    echo "║     建议修复后再进行生产环境测试                               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 1
fi
