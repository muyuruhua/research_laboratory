#!/bin/bash
echo "=== 新增函数调用链完整性检查 ==="
echo ""

echo "[1] P0-1: is_rejection_response调用检查..."
grep -n "is_rejection_response(" afl-fuzz.c verifier.c 2>/dev/null | head -3
echo ""

echo "[2] P0-2: verify_refined_input调用检查..."
echo "  在afl-fuzz.c中的调用:"
grep -n "verify_refined_input(" afl-fuzz.c 2>/dev/null | wc -l
echo "  (应该>0，通常在CEGAR refinement之后调用)"
echo ""

echo "[3] P1-1: state_graph_adaptive_rare_threshold调用检查..."
echo "  在afl-fuzz.c中的调用:"
grep -n "state_graph_adaptive_rare_threshold" afl-fuzz.c 2>/dev/null | wc -l
echo "  (应该>0，用于动态调整稀有转移阈值)"
echo ""

echo "[4] P1-2: state_graph_compute_state_value调用检查..."
echo "  在state-graph.c中的调用:"
grep -n "state_graph_compute_state_value" state-graph.c 2>/dev/null | grep -v "^[0-9]*:double state_graph_compute_state_value" | wc -l
echo "  (应该>0，在select_valuable_target中调用)"
echo ""

echo "[5] state_graph核心函数调用检查..."
echo "  a) state_graph_init:"
grep -cn "state_graph_init(" afl-fuzz.c | grep -v ":0$"
echo "  b) state_graph_add_transition:"
grep -cn "state_graph_add_transition(" afl-fuzz.c | grep -v ":0$"
echo "  c) state_graph_find_rare_transition:"
grep -cn "state_graph_find_rare_transition(" afl-fuzz.c | grep -v ":0$"
echo ""

echo "[6] CEGAR核心函数调用检查..."
echo "  a) cegar_cache_init:"
grep -cn "cegar_cache_init(" afl-fuzz.c | grep -v ":0$"
echo "  b) cegar_cache_lookup:"
grep -cn "cegar_cache_lookup(" afl-fuzz.c | grep -v ":0$"
echo "  c) cegar_cache_insert:"
grep -cn "cegar_cache_insert(" afl-fuzz.c | grep -v ":0$"
echo ""

echo "[7] 检查P0-1软拒绝逻辑是否真正被使用..."
echo "  FTP软拒绝 (421/425):"
grep -B2 -A2 "status_code == 421 || status_code == 425" verifier.c | head -7
echo ""

echo "=== 调用链检查完成 ==="
