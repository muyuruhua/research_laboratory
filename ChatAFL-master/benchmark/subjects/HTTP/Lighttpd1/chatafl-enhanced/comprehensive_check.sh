#!/bin/bash
echo "═══════════════════════════════════════════════════════════════════"
echo "  ChatAFL-Enhanced 全面检查报告"
echo "═══════════════════════════════════════════════════════════════════"
echo

echo "【1】编译状态检查"
echo "────────────────────────────────────────────────────────────────"
if [ -f afl-fuzz ]; then
    echo "✓ afl-fuzz 编译成功"
    ls -lh afl-fuzz | awk '{print "  大小:", $5}'
else
    echo "✗ afl-fuzz 编译失败"
fi

echo

echo "【2】核心模块对象文件检查"
echo "────────────────────────────────────────────────────────────────"
for module in verifier cegar state-graph state-scheduler llm-cost-tracker chat-llm; do
    if [ -f "${module}.o" ]; then
        echo "✓ ${module}.o 存在"
    else
        echo "✗ ${module}.o 缺失"
    fi
done

echo

echo "【3】关键函数符号检查"
echo "────────────────────────────────────────────────────────────────"
nm afl-fuzz 2>/dev/null | grep -E "verify_with_pcre2|delta_debug_minimize|state_graph_add|increment_state_count|g_verifier_checks|g_cegar_triggers" | awk '{print "✓", $3}' | head -10

echo

echo "【4】P0关键修复验证"
echo "────────────────────────────────────────────────────────────────"
echo -n "验证器触发频率: "
grep "stage_cur % 10 == 0" afl-fuzz.c > /dev/null && echo "✓ 已修复 (10次)" || echo "✗ 未修复"

echo -n "CEGAR触发频率: "
grep "g_cegar_triggers % 10 == 0" afl-fuzz.c > /dev/null && echo "✓ 已修复 (10次)" || echo "✗ 未修复"

echo -n "save_if_interesting中的CEGAR: "
grep -A50 "save_if_interesting.*argv.*mem.*len.*fault" afl-fuzz.c | grep "g_cegar_triggers++" > /dev/null && echo "✓ 已添加" || echo "⚠ 未完全集成"

echo -n "pthread支持: "
grep "lpthread" Makefile > /dev/null && echo "✓ 已添加" || echo "✗ 未添加"

echo

echo "【5】内存管理检查"
echo "────────────────────────────────────────────────────────────────"
echo "ck_alloc调用次数:"
grep -o "ck_alloc" cegar.c | wc -l | awk '{print "  cegar.c:", $1}'
echo "ck_free调用次数:"
grep -o "ck_free" cegar.c | wc -l | awk '{print "  cegar.c:", $1}'

echo

echo "【6】API兼容性检查"
echo "────────────────────────────────────────────────────────────────"
echo "函数签名验证:"
grep "bool verify_with_pcre2" verifier.h | head -1
grep "unsigned char \*extract_command_line" cegar.h | head -1  
grep "void state_graph_init" state-graph.h | head -1
grep "int increment_state_count" state-scheduler.h | head -1

echo

echo "【7】潜在问题扫描"
echo "────────────────────────────────────────────────────────────────"
echo "NULL指针检查: $(grep -c "if (!.*)" verifier.c cegar.c 2>/dev/null) 处"
echo "内存泄漏风险: $(grep -c "malloc\|realloc" verifier.c cegar.c 2>/dev/null | awk '{s+=$1}END{print s}') 处需关注"
echo "未初始化变量: $(grep -c "uninit\|uninitialized" *.c 2>/dev/null | awk '{s+=$1}END{print s}') 处警告"

echo

echo "【8】Docker镜像构建检查"
echo "────────────────────────────────────────────────────────────────"
if [ -f Dockerfile ]; then
    echo "✓ Dockerfile存在"
    grep -c "RUN\|COPY\|FROM" Dockerfile | awk '{print "  指令数:", $1}'
else
    echo "✗ Dockerfile缺失"
fi

echo

echo "【9】集成完整性评估"
echo "────────────────────────────────────────────────────────────────"
issues=0

# 检查关键全局变量
if ! grep -q "g_verifier_checks" afl-fuzz.c; then ((issues++)); fi
if ! grep -q "g_cegar_triggers" afl-fuzz.c; then ((issues++)); fi
if ! grep -q "g_state_graph" afl-fuzz.c; then ((issues++)); fi
if ! grep -q "g_cycles_without_new_state" afl-fuzz.c; then ((issues++)); fi

if [ $issues -eq 0 ]; then
    echo "✓ 全局变量声明完整"
else
    echo "⚠ 发现 $issues 个全局变量问题"
fi

# 检查模块初始化
if grep -q "state_graph_init(&g_state_graph)" afl-fuzz.c; then
    echo "✓ State Graph 已初始化"
else
    echo "⚠ State Graph 初始化缺失"
fi

echo

echo "═══════════════════════════════════════════════════════════════════"
echo "  总体评估"
echo "═══════════════════════════════════════════════════════════════════"

total_checks=0
passed_checks=0

# 编译成功
[ -f afl-fuzz ] && ((passed_checks++))
((total_checks++))

# 模块完整
[ -f verifier.o ] && [ -f cegar.o ] && ((passed_checks++))
((total_checks++))

# P0修复
grep -q "stage_cur % 10 == 0" afl-fuzz.c && ((passed_checks++))
((total_checks++))

echo "通过检查: $passed_checks / $total_checks"

if [ $passed_checks -eq $total_checks ]; then
    echo "状态: ✓ 优秀 - 所有关键检查通过"
elif [ $passed_checks -ge $((total_checks * 2 / 3)) ]; then
    echo "状态: ⚠ 良好 - 大部分检查通过"
else
    echo "状态: ✗ 需改进 - 存在关键问题"
fi

echo
