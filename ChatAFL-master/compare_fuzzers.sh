#!/bin/bash
# ChatAFL vs ChatAFL-Enhanced 对比测试脚本
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
print_header() { echo -e "\n${BLUE}========================================${NC}\n${BLUE}$1${NC}\n${BLUE}========================================${NC}\n"; }
print_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
usage() {
    echo "使用方法: $0 <TARGET> <PROTOCOL> <TIMEOUT_MINUTES>"
    echo "示例: $0 LightFTP FTP 60   (注意大小写)"
    echo "      $0 Live555 RTSP 60"
    exit 1
}
[ $# -lt 3 ] && usage
TARGET=$1; PROTOCOL=$2; TIMEOUT_MINUTES=$3
PROTOCOL_LOWER=$(echo "$PROTOCOL" | tr '[:upper:]' '[:lower:]')  # 转换为小写
TIMEOUT_SECONDS=$((TIMEOUT_MINUTES * 60))
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$PROJECT_ROOT"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
COMPARISON_DIR="$PROJECT_ROOT/comparison_results/${TARGET}_${TIMESTAMP}"
mkdir -p "$COMPARISON_DIR"/{chatafl,chatafl-enhanced}
CHATAFL_OUTPUT="${COMPARISON_DIR}/chatafl"
ENHANCED_OUTPUT="${COMPARISON_DIR}/chatafl-enhanced"
CHATAFL_LOG="${COMPARISON_DIR}/chatafl.log"
ENHANCED_LOG="${COMPARISON_DIR}/enhanced.log"
print_header "环境检查"
CHATAFL_BIN="$PROJECT_ROOT/ChatAFL/afl-fuzz"
ENHANCED_BIN="$PROJECT_ROOT/ChatAFL-Enhanced/afl-fuzz"
[ ! -f "$CHATAFL_BIN" ] && { print_error "ChatAFL未构建: cd ChatAFL && make"; exit 1; }
[ ! -f "$ENHANCED_BIN" ] && { print_error "ChatAFL-Enhanced未构建"; exit 1; }
print_success "Fuzzer已构建"
TARGET_DIR="$PROJECT_ROOT/benchmark/subjects/${PROTOCOL}/${TARGET}"
[ ! -d "$TARGET_DIR" ] && { print_error "目标目录不存在: $TARGET_DIR"; ls -d "$PROJECT_ROOT/benchmark/subjects"/*/* 2>/dev/null | sed 's|.*/subjects/||'; exit 1; }
SEED_DIR="$TARGET_DIR/in-${PROTOCOL_LOWER}"  # 使用小写协议名
[ ! -d "$SEED_DIR" ] && { print_error "种子目录不存在: $SEED_DIR"; ls -d "$TARGET_DIR"/in-* 2>/dev/null; exit 1; }

# 根据目标查找正确的二进制文件和设置工作目录
case "$TARGET" in
    *ightFTP*)
        TARGET_BIN="$TARGET_DIR/Source/Release/fftp"
        TARGET_WORKDIR="$TARGET_DIR/Source/Release"
        TARGET_ARGS="fftp.conf 2200"
        CLEAN_SCRIPT="./clean.sh"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+ -N tcp://127.0.0.1/2200 -c $CLEAN_SCRIPT"
        ;;
    *ive555*)
        TARGET_BIN=$(find "$TARGET_DIR" -name "live555MediaServer" 2>/dev/null | head -1)
        TARGET_WORKDIR=$(dirname "$TARGET_BIN")
        TARGET_ARGS=""
        AFL_OPTS="-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -N tcp://127.0.0.1/8554"
        ;;
    *xim*)
        TARGET_BIN=$(find "$TARGET_DIR" -name "exim" -type f -executable 2>/dev/null | head -1)
        TARGET_WORKDIR=$(dirname "$TARGET_BIN")
        TARGET_ARGS="-bdf -q15m"
        AFL_OPTS="-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t 5000+ -N tcp://127.0.0.1/25"
        ;;
    *)
        TARGET_BIN=$(find "$TARGET_DIR" -maxdepth 3 -type f -executable 2>/dev/null | grep -v "\.sh$" | head -1)
        TARGET_WORKDIR=$(dirname "$TARGET_BIN")
        TARGET_ARGS=""
        AFL_OPTS="-P ${PROTOCOL} -D 10000 -q 3 -s 3 -E -K -m none -t 5000+ -N tcp://127.0.0.1/8000"
        ;;
esac

[ ! -f "$TARGET_BIN" ] && { print_error "找不到目标二进制: $TARGET_BIN. 请先构建: cd $TARGET_DIR && docker build"; exit 1; }
print_success "目标: $TARGET_BIN, 种子: $SEED_DIR"
print_header "对比测试: ChatAFL vs ChatAFL-Enhanced"
echo "目标: $TARGET ($PROTOCOL), 时长: $TIMEOUT_MINUTES 分钟"
echo "ChatAFL输出: $CHATAFL_OUTPUT"
echo "Enhanced输出: $ENHANCED_OUTPUT"
read -p "开始测试? (y/n) " -n 1 -r; echo; [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
print_header "启动ChatAFL对${TARGET}测试"
(export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1
cd "$TARGET_WORKDIR"
timeout ${TIMEOUT_SECONDS}s "$CHATAFL_BIN" -i "$SEED_DIR" -o "$CHATAFL_OUTPUT" $AFL_OPTS -- "$TARGET_BIN" $TARGET_ARGS 2>&1 | tee "$CHATAFL_LOG") &
CHATAFL_PID=$!; print_success "ChatAFL启动 (PID: $CHATAFL_PID)"; sleep 5
print_header "启动ChatAFL-Enhanced对${TARGET}测试"
(export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CRASHES=1 CHATAFL_ENHANCED=1 CEGAR_CACHE_DIR="${ENHANCED_OUTPUT}/.cegar_cache"
mkdir -p "$CEGAR_CACHE_DIR"
cd "$TARGET_WORKDIR"
timeout ${TIMEOUT_SECONDS}s "$ENHANCED_BIN" -i "$SEED_DIR" -o "$ENHANCED_OUTPUT" $AFL_OPTS -- "$TARGET_BIN" $TARGET_ARGS 2>&1 | tee "$ENHANCED_LOG") &
ENHANCED_PID=$!; print_success "ChatAFL-Enhanced启动 (PID: $ENHANCED_PID)"
print_header "等待测试完成 ($TIMEOUT_MINUTES 分钟)"
echo "ChatAFL PID: $CHATAFL_PID, Enhanced PID: $ENHANCED_PID"
echo "日志: tail -f $CHATAFL_LOG"
echo "      tail -f $ENHANCED_LOG"
wait $CHATAFL_PID 2>/dev/null; print_success "ChatAFL完成"
wait $ENHANCED_PID 2>/dev/null; print_success "Enhanced完成"
print_header "生成对比报告"
COMPARISON_LOG="${COMPARISON_DIR}/report.txt"
echo "===== ChatAFL vs ChatAFL-Enhanced 对比报告 =====" > "$COMPARISON_LOG"
echo "目标: $TARGET ($PROTOCOL), 时长: $TIMEOUT_MINUTES分钟" >> "$COMPARISON_LOG"
echo "时间: $(date)" >> "$COMPARISON_LOG"
echo "" >> "$COMPARISON_LOG"
if [ -f "${CHATAFL_OUTPUT}/fuzzer_stats" ]; then
    echo "[ChatAFL]" >> "$COMPARISON_LOG"
    grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|bitmap_cvg" "${CHATAFL_OUTPUT}/fuzzer_stats" >> "$COMPARISON_LOG"
    echo "" >> "$COMPARISON_LOG"
fi
if [ -f "${ENHANCED_OUTPUT}/fuzzer_stats" ]; then
    echo "[ChatAFL-Enhanced]" >> "$COMPARISON_LOG"
    grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|bitmap_cvg" "${ENHANCED_OUTPUT}/fuzzer_stats" >> "$COMPARISON_LOG"
    echo "" >> "$COMPARISON_LOG"
    echo "[Enhanced特有功能]" >> "$COMPARISON_LOG"
    [ -d "${ENHANCED_OUTPUT}/.stt_export" ] && echo "STT导出: $(ls "${ENHANCED_OUTPUT}/.stt_export"/*.dot 2>/dev/null | wc -l)" >> "$COMPARISON_LOG"
    [ -d "${ENHANCED_OUTPUT}/.cegar_cache" ] && echo "CEGAR补丁: $(ls "${ENHANCED_OUTPUT}/.cegar_cache"/*.json 2>/dev/null | wc -l)" >> "$COMPARISON_LOG"
fi
cat "$COMPARISON_LOG"
print_success "完成! 结果保存在: $COMPARISON_DIR"
echo "查看报告: cat $COMPARISON_LOG"
echo "查看详细日志: cat $CHATAFL_LOG"
echo "                cat $ENHANCED_LOG"
