#!/bin/bash
echo "=== 数据结构一致性检查 ==="
echo ""

echo "[1] StateNode结构字段使用检查..."
grep -n "first_discovered" state-graph.c verifier.c state-scheduler.c 2>/dev/null | head -5
grep -n "first_seen_time" state-graph.c verifier.c state-scheduler.c 2>/dev/null && echo "❌ 错误: 发现过时字段first_seen_time" || echo "✓ 正确: 未使用过时字段first_seen_time"
echo ""

echo "[2] CEGARCache timestamp字段检查..."
grep -n "time_t timestamp" cegar.h && echo "✓ P1-3: CEGAR缓存timestamp字段已定义" || echo "❌ 缺失timestamp字段"
grep -n "entry->timestamp = time(NULL)" cegar.c | head -1 && echo "✓ 缓存写入时设置时间戳" || echo "⚠️  未设置时间戳"
echo ""

echo "[3] verify_refined_input函数签名检查..."
grep -n "bool verify_refined_input" verifier.h verifier.c | head -3
echo ""

echo "[4] 新增函数声明与实现匹配检查..."
echo "  a) verify_refined_input:"
grep -c "bool verify_refined_input" verifier.h
grep -c "bool verify_refined_input" verifier.c
echo "  b) state_graph_adaptive_rare_threshold:"
grep -c "state_graph_adaptive_rare_threshold" state-graph.h
grep -c "state_graph_adaptive_rare_threshold" state-graph.c
echo "  c) state_graph_compute_state_value:"
grep -c "state_graph_compute_state_value" state-graph.h
grep -c "state_graph_compute_state_value" state-graph.c
echo ""

echo "[5] 统计数据集成检查..."
grep -n "g_cegar_triggers\|g_cegar_success\|g_cegar_cache_hits" afl-fuzz.c | grep "fprintf" | wc -l
echo "   (应该≥3: triggers, success, cache_hits)"
echo ""

echo "[6] 主循环集成检查..."
grep -n "state_graph_find_rare_transition" afl-fuzz.c | head -1
grep -n "state_graph_add_transition" afl-fuzz.c | head -1
grep -n "cegar_cache_lookup" afl-fuzz.c | head -1
echo ""

echo "=== 检查完成 ==="
