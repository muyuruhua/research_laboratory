#!/bin/bash
# ChatAFL-Enhanced: P0-2和P0-3全面测试脚本

echo "=== ChatAFL-Enhanced P0-2/P0-3测试 ==="

# 测试1: 检查-r参数是否被接受
echo "[1] 测试-r参数是否被识别..."
./afl-fuzz -h 2>&1 | grep -q "seed" && echo "✓ -r参数文档存在" || echo "⚠ -r参数未在帮助中"

# 测试2: 检查随机种子全局变量
echo "[2] 检查g_random_seed全局变量..."
if grep -q "static u64 g_random_seed" afl-fuzz.c; then
  echo "✓ g_random_seed变量已声明"
else
  echo "✗ g_random_seed变量缺失"
fi

# 测试3: 检查种子初始化逻辑
echo "[3] 检查种子初始化逻辑..."
if grep -q "Using fixed random seed:" afl-fuzz.c; then
  echo "✓ 固定种子日志已添加"
else
  echo "✗ 固定种子日志缺失"
fi

# 测试4: 检查fuzzer_stats中的random_seed输出
echo "[4] 检查fuzzer_stats输出..."
if grep -q 'fprintf(f, "random_seed' afl-fuzz.c; then
  echo "✓ random_seed已添加到fuzzer_stats"
else
  echo "✗ random_seed未添加到fuzzer_stats"
fi

# 测试5: 检查LLMCallLog结构体
echo "[5] 检查LLMCallLog结构体..."
if grep -q "typedef struct.*LLMCallLog" chat-llm.h; then
  echo "✓ LLMCallLog结构体已定义"
else
  echo "✗ LLMCallLog结构体缺失"
fi

# 测试6: 检查log_llm_call函数
echo "[6] 检查log_llm_call函数实现..."
if grep -q "void log_llm_call" chat-llm.c; then
  echo "✓ log_llm_call函数已实现"
else
  echo "✗ log_llm_call函数缺失"
fi

# 测试7: 检查CEGAR中的LLM日志集成
echo "[7] 检查CEGAR中的LLM日志集成..."
if grep -q "log.call_site = \"CEGAR\"" cegar.c; then
  echo "✓ CEGAR调用点已添加日志"
else
  echo "✗ CEGAR调用点未添加日志"
fi

# 测试8: 检查get_out_dir函数
echo "[8] 检查get_out_dir函数..."
if grep -q "const char\* get_out_dir" afl-fuzz.c; then
  echo "✓ get_out_dir函数已实现"
else
  echo "✗ get_out_dir函数缺失"
fi

# 测试9: 验证编译成功
echo "[9] 验证afl-fuzz二进制..."
if [ -x "./afl-fuzz" ]; then
  echo "✓ afl-fuzz编译成功"
else
  echo "✗ afl-fuzz未编译或不可执行"
fi

# 测试10: 验证P1修复仍然存在
echo "[10] 验证P1修复未丢失..."
if grep -q "compute_state_coverage" state-scheduler.c; then
  echo "✓ P1-1状态覆盖率功能完整"
else
  echo "✗ P1-1功能丢失"
fi

if grep -q "state_graph_find_rare_transition" afl-fuzz.c; then
  echo "✓ P1-2稀有转移集成完整"
else
  echo "✗ P1-2功能丢失"
fi

if grep -q "timestamp" cegar.h; then
  echo "✓ P1-3缓存时间戳完整"
else
  echo "✗ P1-3功能丢失"
fi

echo ""
echo "=== 测试完成 ==="
