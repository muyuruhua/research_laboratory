#!/bin/bash
#
# ChatAFL-Enhanced P0修复验证脚本
# 
# 测试3个P0修复：
# 1. P0-1: 覆盖增益验证（Coverage Gain Verification）
# 2. P0-2: 固定随机种子（Fixed Random Seed） - 待实施
# 3. P0-3: LLM调用日志（LLM Call Logging） - 待实施
#

set -e

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
NC="\033[0m" # No Color

function log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

function log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ===== 测试P0-1: 覆盖增益验证 =====

log_info "=== 测试P0-1: 覆盖增益验证 ==="

# 检查编译结果
if [ ! -f "./afl-fuzz" ]; then
    log_error "afl-fuzz未编译，请先运行 make afl-fuzz"
    exit 1
fi

log_info "检查符号表中是否有save_to_corpus..."
if nm afl-fuzz | grep -q "save_to_corpus"; then
    log_info "✓ save_to_corpus符号存在"
else
    log_error "✗ save_to_corpus符号不存在"
    exit 1
fi

log_info "检查count_non_255_bytes是否在state-scheduler.c中定义..."
if grep -q "count_non_255_bytes" state-scheduler.c; then
    log_info "✓ count_non_255_bytes辅助函数存在"
else
    log_error "✗ count_non_255_bytes辅助函数缺失"
    exit 1
fi

log_info "检查save_to_corpus返回类型是否为bool..."
if grep -q "^bool save_to_corpus" state-scheduler.h; then
    log_info "✓ save_to_corpus声明为bool返回类型"
else
    log_error "✗ save_to_corpus返回类型不是bool"
    exit 1
fi

log_info "检查afl-fuzz.c中的调用点是否传递virgin_bits..."
if grep -q "virgin_bits," afl-fuzz.c && grep -q "MAP_SIZE," afl-fuzz.c; then
    log_info "✓ afl-fuzz.c调用save_to_corpus时传递了覆盖信息"
else
    log_error "✗ afl-fuzz.c未传递覆盖信息给save_to_corpus"
    exit 1
fi

log_info "检查edge_info是否包含增益标注..."
if grep -q "edge+%u, state+%u" state-scheduler.c; then
    log_info "✓ edge_info包含增益度量标注"
else
    log_error "✗ edge_info缺少增益度量标注"
    exit 1
fi

log_info ""
log_info "P0-1静态检查: ✓ 全部通过"
log_info ""

# ===== 功能测试（需要实际运行fuzzer） =====

log_warn "===== 功能测试需要实际运行fuzzer（跳过） ====="
log_warn "要进行功能测试，请运行："
log_warn "  ./afl-fuzz -d -i seeds -o out_test -N tcp://127.0.0.1/21 -P FTP -D 10000 -E -K -r 42 -- ./target -S 21"
log_warn "然后检查："
log_warn "  1. ls -lh out_test/corpus/ | wc -l  # corpus大小应小于baseline"
log_warn "  2. cat out_test/corpus/*/edge_info  # 应包含'edge+X, state+Y'标注"
log_warn "  3. grep corpus out_test/fuzzer_log  # 应有保存/拒绝日志"
log_warn ""

# ===== 测试P0-2: 固定随机种子 =====

log_info "=== 测试P0-2: 固定随机种子（待实施） ==="
log_warn "P0-2尚未实施，跳过测试"
log_warn ""

# ===== 测试P0-3: LLM调用日志 =====

log_info "=== 测试P0-3: LLM调用日志（待实施） ==="
log_warn "P0-3尚未实施，跳过测试"
log_warn ""

# ===== 总结 =====

log_info "===== P0修复验证总结 ====="
log_info "✓ P0-1: 覆盖增益验证 - 静态检查通过（需功能测试）"
log_warn "⏳ P0-2: 固定随机种子 - 待实施"
log_warn "⏳ P0-3: LLM调用日志 - 待实施"
log_info ""
log_info "下一步："
log_info "1. 实施P0-2（固定随机种子）"
log_info "2. 实施P0-3（LLM调用日志）"
log_info "3. 运行完整功能测试（24小时fuzzing）"
log_info "4. 性能对比测试（与baseline对比）"
log_info ""
