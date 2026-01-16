#!/bin/bash
echo "=== 回归测试：确保现有功能未被破坏 ==="
echo ""

echo "[1] 核心状态图函数完整性..."
for func in state_graph_init state_graph_add_transition state_graph_find_rare_transition state_graph_export_dot; do
  count=$(nm afl-fuzz 2>/dev/null | grep -c " $func$")
  if [ "$count" -ge 1 ]; then
    echo "  ✅ $func"
  else
    echo "  ❌ $func (缺失)"
  fi
done
echo ""

echo "[2] CEGAR核心函数完整性..."
for func in cegar_cache_init cegar_cache_lookup cegar_cache_add delta_debug_minimize; do
  count=$(nm afl-fuzz 2>/dev/null | grep -c " $func$")
  if [ "$count" -ge 1 ]; then
    echo "  ✅ $func"
  else
    echo "  ❌ $func (缺失)"
  fi
done
echo ""

echo "[3] 验证器核心函数完整性..."
for func in verify_protocol_sequence verify_json_grammar is_rejection_response compute_enhanced_state_id; do
  count=$(nm afl-fuzz 2>/dev/null | grep -c " $func$")
  if [ "$count" -ge 1 ]; then
    echo "  ✅ $func"
  else
    echo "  ❌ $func (缺失)"
  fi
done
echo ""

echo "[4] 统计变量完整性..."
for var in g_cegar_triggers g_cegar_success g_cegar_cache_hits g_cycles_without_new_state; do
  count=$(grep -c "$var" afl-fuzz.c)
  if [ "$count" -ge 2 ]; then
    echo "  ✅ $var (引用${count}次)"
  else
    echo "  ⚠️  $var (引用${count}次，偏少)"
  fi
done
echo ""

echo "[5] 主循环关键逻辑检查..."
grep -c "state_graph_add_transition" afl-fuzz.c | xargs -I {} echo "  状态转移记录: {} 处"
grep -c "cegar_cache_lookup" afl-fuzz.c | xargs -I {} echo "  CEGAR缓存查询: {} 处"
grep -c "chat_with_llm" afl-fuzz.c | xargs -I {} echo "  LLM调用: {} 处"
grep -c "save_if_interesting" afl-fuzz.c | xargs -I {} echo "  种子保存: {} 处"
echo ""

echo "[6] 新增集成未破坏原有逻辑..."
# 检查关键原有代码是否还在
grep -q "queue_cycle % 100 == 0 && state_aware_mode" afl-fuzz.c && echo "  ✅ 稀有转移检测逻辑完整" || echo "  ❌ 稀有转移检测逻辑损坏"
grep -q "g_cycles_without_new_state >= 10 && protocol_name" afl-fuzz.c && echo "  ✅ Plateau触发逻辑完整" || echo "  ❌ Plateau触发逻辑损坏"
grep -q "g_cegar_triggers % 50 == 0 && out_buf && len > 10" afl-fuzz.c && echo "  ✅ CEGAR触发逻辑完整" || echo "  ❌ CEGAR触发逻辑损坏"
echo ""

echo "=== 回归测试完成 ==="
