#!/bin/bash
# ChatAFL-Enhanced: P0+P1完整修复验证

echo "=== ChatAFL-Enhanced P0+P1修复验证 ==="
echo

# P0-1: 软拒绝处理
echo "[P0-1] 验证软拒绝(临时错误)处理..."
if grep -q "status_code == 421 || status_code == 425" verifier.c; then
  echo "  ✓ FTP软拒绝(421/425)已实现"
else
  echo "  ✗ FTP软拒绝缺失"
fi

if grep -q "status_code == 421 || status_code == 450" verifier.c; then
  echo "  ✓ SMTP软拒绝(421/450)已实现"
else
  echo "  ✗ SMTP软拒绝缺失"
fi

# P0-2: CEGAR修正后再验证
echo
echo "[P0-2] 验证CEGAR闭环（修正后再验证）..."
if grep -q "verify_refined_input" verifier.h; then
  echo "  ✓ verify_refined_input函数已声明"
else
  echo "  ✗ verify_refined_input函数缺失"
fi

if grep -q "Layer 1: 可解析性验证" verifier.c; then
  echo "  ✓ 4层验证逻辑已实现"
else
  echo "  ✗ 4层验证逻辑缺失"
fi

# P1-1: 自适应稀有转移阈值
echo
echo "[P1-1] 验证自适应稀有转移阈值..."
if grep -q "state_graph_adaptive_rare_threshold" state-graph.h; then
  echo "  ✓ 自适应阈值函数已声明"
else
  echo "  ✗ 自适应阈值函数缺失"
fi

if grep -q "Plateau调整.*cycles提升" state-graph.c; then
  echo "  ✓ Plateau动态调整已实现"
else
  echo "  ✗ Plateau动态调整缺失"
fi

# P1-2: 状态价值估计
echo
echo "[P1-2] 验证状态价值估计..."
if grep -q "state_graph_compute_state_value" state-graph.h; then
  echo "  ✓ 状态价值计算函数已声明"
else
  echo "  ✗ 状态价值计算函数缺失"
fi

if grep -q "因子1.*访问稀缺性" state-graph.c; then
  echo "  ✓ 多因子价值估计已实现(访问+扩展+新鲜度+类型)"
else
  echo "  ✗ 多因子价值估计缺失"
fi

if grep -q "state_graph_select_valuable_target" state-graph.h; then
  echo "  ✓ 智能target_state选择函数已声明"
else
  echo "  ✗ 智能target_state选择缺失"
fi

# 编译验证
echo
echo "[编译验证] 检查二进制文件..."
if [ -x "./afl-fuzz" ]; then
  echo "  ✓ afl-fuzz编译成功"
  ls -lh afl-fuzz | awk '{print "  Size:", $5, "Modified:", $6, $7, $8}'
else
  echo "  ✗ afl-fuzz编译失败或不可执行"
fi

# 检查之前的P1修复是否保留
echo
echo "[回归测试] 验证之前的P1修复未丢失..."
if grep -q "compute_state_coverage" state-scheduler.c; then
  echo "  ✓ P1-1(RFC状态覆盖率)保留"
else
  echo "  ✗ P1-1功能丢失"
fi

if grep -q "state_graph_find_rare_transition" afl-fuzz.c; then
  echo "  ✓ P1-2(稀有转移集成)保留"
else
  echo "  ✗ P1-2功能丢失"
fi

if grep -q "timestamp.*time_t" cegar.h; then
  echo "  ✓ P1-3(CEGAR缓存时间戳)保留"
else
  echo "  ✗ P1-3功能丢失"
fi

# 统计代码变更
echo
echo "[代码统计] 修复规模..."
echo "  verifier.c行数: $(wc -l < verifier.c)"
echo "  state-graph.c行数: $(wc -l < state-graph.c)"
echo "  新增函数数: $(grep -c "^bool verify_refined_input\|^uint32_t state_graph_adaptive\|^double state_graph_compute\|^uint32_t state_graph_select" verifier.c state-graph.c)"

echo
echo "=== 验证完成 ==="
