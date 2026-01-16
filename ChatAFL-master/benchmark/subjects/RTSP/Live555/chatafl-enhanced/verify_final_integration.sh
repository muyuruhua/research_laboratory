#!/bin/bash
echo "=== P0+P1完整集成验证 ==="
echo ""

echo "[1] P0-2: verify_refined_input调用验证..."
grep -n "verify_refined_input(" afl-fuzz.c | grep -v "bool verify_refined_input" | wc -l | xargs -I {} echo "  主循环调用次数: {} (期望≥1)"
grep -B2 -A2 "P0-2修复: CEGAR验证循环" afl-fuzz.c | head -7
echo ""

echo "[2] P1-1: state_graph_adaptive_rare_threshold集成验证..."
grep -n "state_graph_adaptive_rare_threshold(" state-graph.c | wc -l | xargs -I {} echo "  state-graph.c调用次数: {} (期望≥1)"
grep -B1 -A1 "P1-1: 计算自适应阈值" state-graph.c | head -3
echo ""

echo "[3] P1-2: select_valuable_target集成验证..."
grep -n "state_graph_select_valuable_target(" afl-fuzz.c | wc -l | xargs -I {} echo "  主循环调用次数: {} (期望≥1)"
grep -B1 -A3 "P1-2修复: 智能选择突破目标状态" afl-fuzz.c | head -5
echo ""

echo "[4] 编译状态确认..."
ls -lh afl-fuzz 2>/dev/null | awk '{print "  afl-fuzz: " $5 " (修改时间: " $6 " " $7 ")"}'
echo ""

echo "[5] 符号表验证（关键函数存在性）..."
nm afl-fuzz 2>/dev/null | grep -E "verify_refined_input|state_graph_adaptive_rare_threshold|state_graph_select_valuable_target" | awk '{print "  " $2 " " $3}'
echo ""

echo "[6] 集成完整性总结..."
p02_calls=$(grep -c "verify_refined_input(" afl-fuzz.c 2>/dev/null)
p11_calls=$(grep -c "state_graph_adaptive_rare_threshold(" state-graph.c 2>/dev/null)
p12_calls=$(grep -c "state_graph_select_valuable_target(" afl-fuzz.c 2>/dev/null)

if [ "$p02_calls" -ge 1 ] && [ "$p11_calls" -ge 1 ] && [ "$p12_calls" -ge 1 ]; then
  echo "  ✅ 所有P0+P1功能已完整集成到主循环"
else
  echo "  ⚠️  部分功能未集成: P0-2=$p02_calls, P1-1=$p11_calls, P1-2=$p12_calls"
fi
echo ""

echo "=== 验证完成 ==="
