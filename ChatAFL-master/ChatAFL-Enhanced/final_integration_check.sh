#!/bin/bash
echo "=== ChatAFL-Enhanced 集成完整性检查 ==="
echo ""

echo "[1] 编译状态检查..."
ls -lh afl-fuzz afl-replay aflnet-replay 2>/dev/null | awk '{print "  " $9 ": " $5}' || echo "  ❌ 主要二进制文件缺失"
echo ""

echo "[2] 新增模块对象文件检查..."
for obj in verifier.o cegar.o state-scheduler.o state-graph.o; do
  if [ -f "$obj" ]; then
    echo "  ✓ $obj ($(stat -c%s $obj) bytes)"
  else
    echo "  ❌ $obj 缺失"
  fi
done
echo ""

echo "[3] 核心头文件检查..."
for header in verifier.h cegar.h state-scheduler.h state-graph.h protocol-spec.h; do
  if [ -f "$header" ]; then
    lines=$(wc -l < "$header")
    echo "  ✓ $header ($lines lines)"
  else
    echo "  ❌ $header 缺失"
  fi
done
echo ""

echo "[4] 主程序模块集成检查..."
echo "  a) afl-fuzz.c包含的头文件:"
grep -E "#include \"(verifier|cegar|state-scheduler|state-graph)\.h\"" afl-fuzz.c | sed 's/^/    /'
echo "  b) afl-fuzz依赖的.o文件数量:"
grep "afl-fuzz:" Makefile | grep -o '\w\+\.o' | wc -l
echo "     (应该包含: aflnet.o chat-llm.o verifier.o cegar.o state-scheduler.o state-graph.o)"
echo ""

echo "[5] 库依赖完整性检查..."
echo "  系统库依赖:"
ldd afl-fuzz 2>/dev/null | grep -E "libcurl|libjson-c|libpcre2|libgvc|libcgraph" | sed 's/^/    /' || echo "    ⚠️  无法检查ldd (可能需要root)"
echo ""
echo "  Makefile库链接标志:"
grep "afl-fuzz:" Makefile -A1 | grep -- "-l" | grep -o -- "-l[a-z0-9-]*" | sort -u | sed 's/^/    /'
echo ""

echo "[6] 关键函数符号检查..."
nm afl-fuzz 2>/dev/null | grep -E "verify_refined_input|state_graph_adaptive_rare_threshold|state_graph_compute_state_value|cegar_cache_lookup" | awk '{print "  " $2 " " $3}' || echo "  ⚠️  无法检查符号表"
echo ""

echo "[7] P0+P1功能代码存在性检查..."
echo "  P0-1 (软拒绝):"
grep -c "status_code == 421 || status_code == 425" verifier.c
echo "  P0-2 (CEGAR验证循环):"
grep -c "bool verify_refined_input" verifier.c
echo "  P1-1 (自适应阈值):"
grep -c "state_graph_adaptive_rare_threshold" state-graph.c
echo "  P1-2 (状态价值评估):"
grep -c "state_graph_compute_state_value" state-graph.c
echo "  P1-3 (CEGAR缓存时间戳):"
grep -c "time_t timestamp" cegar.h
echo ""

echo "[8] 统计数据输出集成检查..."
grep -c "cegar_triggers\|cegar_success\|cegar_cache_hits" afl-fuzz.c
echo "   (应该>=10: 变量定义+输出语句)"
echo ""

echo "=== 检查完成 ==="
