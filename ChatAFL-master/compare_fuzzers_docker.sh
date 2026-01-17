#!/bin/bash
# ChatAFL vs ChatAFL-Enhanced 对比测试脚本 (Docker版本)
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

print_header() { echo -e "\n${BLUE}========================================${NC}\n${BLUE}$1${NC}\n${BLUE}========================================${NC}\n"; }
print_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

usage() {
    echo "使用方法: $0 <TARGET> <PROTOCOL> <TIMEOUT_MINUTES>"
    echo "示例: $0 LightFTP FTP 60"
    echo "      $0 Live555 RTSP 60"
    echo "      $0 Exim SMTP 60"
    echo ""
    echo "支持的目标: LightFTP, BFTPD, ProFTPD, PureFTPD, Live555, Exim, Kamailio, forked-daapd, Lighttpd1"
    exit 1
}

[ $# -lt 3 ] && usage

TARGET=$1
PROTOCOL=$2
TIMEOUT_MINUTES=$3
TIMEOUT_SECONDS=$((TIMEOUT_MINUTES * 60))

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
COMPARISON_DIR="$PROJECT_ROOT/comparison_results/${TARGET}_${TIMESTAMP}"
mkdir -p "$COMPARISON_DIR"/{chatafl,chatafl-enhanced}

CHATAFL_OUTPUT="${COMPARISON_DIR}/chatafl"
ENHANCED_OUTPUT="${COMPARISON_DIR}/chatafl-enhanced"
CHATAFL_LOG="${COMPARISON_DIR}/chatafl.log"
ENHANCED_LOG="${COMPARISON_DIR}/enhanced.log"

print_header "环境检查"

# 检查Docker镜像是否存在
DOCKER_IMAGE=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]')
if ! docker images | grep -q "$DOCKER_IMAGE"; then
    print_error "Docker镜像不存在: $DOCKER_IMAGE"
    echo "请先构建镜像: cd benchmark/subjects/${PROTOCOL}/${TARGET} && docker build -t $DOCKER_IMAGE ."
    exit 1
fi
print_success "Docker镜像已就绪: $DOCKER_IMAGE"

# 根据目标设置容器内的路径和参数
case "$TARGET" in
    LightFTP|lightftp)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/LightFTP/Source/Release"
        CONTAINER_TARGET="./fftp"
        TARGET_ARGS="fftp.conf 2200"
        SEED_DIR="/home/ubuntu/experiments/in-ftp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/ftpclean"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+ -N tcp://127.0.0.1/2200 -c $CLEAN_SCRIPT"
        ;;
    BFTPD|bftpd)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/BFTPD"
        CONTAINER_TARGET="./bftpd"
        TARGET_ARGS="-c bftpd.conf -D"
        SEED_DIR="/home/ubuntu/experiments/in-ftp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/ftpclean"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+ -N tcp://127.0.0.1/2200 -c $CLEAN_SCRIPT"
        ;;
    ProFTPD|proftpd)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/ProFTPD"
        CONTAINER_TARGET="./proftpd"
        TARGET_ARGS="-n -c proftpd.conf"
        SEED_DIR="/home/ubuntu/experiments/in-ftp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/ftpclean"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+ -N tcp://127.0.0.1/2200 -c $CLEAN_SCRIPT"
        ;;
    PureFTPD|pure-ftpd)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/PureFTPD"
        CONTAINER_TARGET="./pure-ftpd"
        TARGET_ARGS="-A -B"
        SEED_DIR="/home/ubuntu/experiments/in-ftp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/ftpclean"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+ -N tcp://127.0.0.1/2200 -c $CLEAN_SCRIPT"
        ;;
    Live555|live555)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/Live555"
        CONTAINER_TARGET="./live555MediaServer"
        TARGET_ARGS="8554"
        SEED_DIR="/home/ubuntu/experiments/in-rtsp"
        AFL_OPTS="-d -P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -N tcp://127.0.0.1/8554"
        ;;
    Exim|exim)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/Exim"
        CONTAINER_TARGET="./exim"
        TARGET_ARGS="-bdf -q15m"
        SEED_DIR="/home/ubuntu/experiments/in-smtp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/smtpclean"
        AFL_OPTS="-d -P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t 5000+ -N tcp://127.0.0.1/25 -c $CLEAN_SCRIPT"
        ;;
    *)
        print_error "不支持的目标: $TARGET"
        usage
        ;;
esac

print_header "对比测试: ChatAFL vs ChatAFL-Enhanced"
echo "目标: $TARGET ($PROTOCOL), 时长: $TIMEOUT_MINUTES 分钟"
echo "Docker镜像: $DOCKER_IMAGE"
echo "ChatAFL输出: $CHATAFL_OUTPUT"
echo "Enhanced输出: $ENHANCED_OUTPUT"
read -p "开始测试? (y/n) " -n 1 -r
echo
[[ ! $REPLY =~ ^[Yy]$ ]] && exit 0

print_header "启动ChatAFL容器测试${TARGET}"

# 运行ChatAFL容器
docker run -d \
    --name "chatafl_${TARGET}_${TIMESTAMP}" \
    -v "${CHATAFL_OUTPUT}:/home/ubuntu/output" \
    "$DOCKER_IMAGE" \
    bash -c "cd $CONTAINER_WORKDIR && timeout ${TIMEOUT_SECONDS}s /home/ubuntu/chatafl/afl-fuzz -i $SEED_DIR -o /home/ubuntu/output $AFL_OPTS -- $CONTAINER_TARGET $TARGET_ARGS" \
    > /dev/null 2>&1

if [ $? -eq 0 ]; then
    print_success "ChatAFL容器已启动"
    CHATAFL_CONTAINER="chatafl_${TARGET}_${TIMESTAMP}"
else
    print_error "ChatAFL容器启动失败"
    exit 1
fi

sleep 5

print_header "启动ChatAFL-Enhanced容器测试${TARGET}"

# 运行ChatAFL-Enhanced容器
docker run -d \
    --name "enhanced_${TARGET}_${TIMESTAMP}" \
    -v "${ENHANCED_OUTPUT}:/home/ubuntu/output" \
    -e CHATAFL_ENHANCED=1 \
    "$DOCKER_IMAGE" \
    bash -c "cd $CONTAINER_WORKDIR && timeout ${TIMEOUT_SECONDS}s /home/ubuntu/chatafl-enhanced/afl-fuzz -i $SEED_DIR -o /home/ubuntu/output $AFL_OPTS -- $CONTAINER_TARGET $TARGET_ARGS" \
    > /dev/null 2>&1

if [ $? -eq 0 ]; then
    print_success "ChatAFL-Enhanced容器已启动"
    ENHANCED_CONTAINER="enhanced_${TARGET}_${TIMESTAMP}"
else
    print_error "ChatAFL-Enhanced容器启动失败"
    docker stop "$CHATAFL_CONTAINER" 2>/dev/null
    docker rm "$CHATAFL_CONTAINER" 2>/dev/null
    exit 1
fi

print_header "等待测试完成 ($TIMEOUT_MINUTES 分钟)"
echo "ChatAFL容器: $CHATAFL_CONTAINER"
echo "Enhanced容器: $ENHANCED_CONTAINER"
echo ""
echo "实时监控日志:"
echo "  docker logs -f $CHATAFL_CONTAINER"
echo "  docker logs -f $ENHANCED_CONTAINER"
echo ""

# 显示进度
START_TIME=$(date +%s)
while true; do
    CHATAFL_RUNNING=$(docker ps -q -f name="$CHATAFL_CONTAINER" 2>/dev/null)
    ENHANCED_RUNNING=$(docker ps -q -f name="$ENHANCED_CONTAINER" 2>/dev/null)
    
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    REMAINING=$((TIMEOUT_SECONDS - ELAPSED))
    
    if [ -z "$CHATAFL_RUNNING" ] && [ -z "$ENHANCED_RUNNING" ]; then
        echo ""
        print_success "两个容器都已完成"
        break
    fi
    
    if [ $REMAINING -le 0 ]; then
        echo ""
        print_info "超时，停止容器..."
        docker stop "$CHATAFL_CONTAINER" "$ENHANCED_CONTAINER" 2>/dev/null
        break
    fi
    
    # 显示当前统计
    if [ -f "${CHATAFL_OUTPUT}/fuzzer_stats" ]; then
        CHATAFL_EXECS=$(grep "execs_done" "${CHATAFL_OUTPUT}/fuzzer_stats" 2>/dev/null | awk '{print $3}' || echo "0")
    else
        CHATAFL_EXECS="启动中..."
    fi
    
    if [ -f "${ENHANCED_OUTPUT}/fuzzer_stats" ]; then
        ENHANCED_EXECS=$(grep "execs_done" "${ENHANCED_OUTPUT}/fuzzer_stats" 2>/dev/null | awk '{print $3}' || echo "0")
    else
        ENHANCED_EXECS="启动中..."
    fi
    
    printf "\r剩余时间: %02d:%02d | ChatAFL执行数: %s | Enhanced执行数: %s     " \
        $((REMAINING / 60)) $((REMAINING % 60)) "$CHATAFL_EXECS" "$ENHANCED_EXECS"
    
    sleep 10
done

# 获取日志
print_header "收集日志"
docker logs "$CHATAFL_CONTAINER" > "$CHATAFL_LOG" 2>&1
docker logs "$ENHANCED_CONTAINER" > "$ENHANCED_LOG" 2>&1
print_success "日志已保存"

# 清理容器
print_info "清理容器..."
docker rm "$CHATAFL_CONTAINER" "$ENHANCED_CONTAINER" 2>/dev/null
print_success "容器已清理"

print_header "生成对比报告"

COMPARISON_LOG="${COMPARISON_DIR}/report.txt"

{
    echo "===== ChatAFL vs ChatAFL-Enhanced 对比报告 ====="
    echo "目标: $TARGET ($PROTOCOL), 时长: $TIMEOUT_MINUTES分钟"
    echo "时间: $(date)"
    echo ""
    
    if [ -f "${CHATAFL_OUTPUT}/fuzzer_stats" ]; then
        echo "========== ChatAFL 统计 =========="
        grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|unique_hangs|bitmap_cvg|last_path" "${CHATAFL_OUTPUT}/fuzzer_stats"
        echo ""
        
        if [ -d "${CHATAFL_OUTPUT}/crashes" ]; then
            CRASH_COUNT=$(ls "${CHATAFL_OUTPUT}/crashes" 2>/dev/null | grep -v "README.txt" | wc -l)
            echo "崩溃文件数: $CRASH_COUNT"
        fi
        echo ""
    else
        echo "ChatAFL未生成统计数据"
        echo ""
    fi
    
    if [ -f "${ENHANCED_OUTPUT}/fuzzer_stats" ]; then
        echo "========== ChatAFL-Enhanced 统计 =========="
        grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|unique_hangs|bitmap_cvg|last_path" "${ENHANCED_OUTPUT}/fuzzer_stats"
        echo ""
        
        if [ -d "${ENHANCED_OUTPUT}/crashes" ]; then
            CRASH_COUNT=$(ls "${ENHANCED_OUTPUT}/crashes" 2>/dev/null | grep -v "README.txt" | wc -l)
            echo "崩溃文件数: $CRASH_COUNT"
        fi
        
        echo ""
        echo "========== Enhanced特有功能 =========="
        
        if [ -d "${ENHANCED_OUTPUT}/.stt_export" ]; then
            STT_COUNT=$(ls "${ENHANCED_OUTPUT}/.stt_export"/*.dot 2>/dev/null | wc -l)
            echo "STT导出文件数: $STT_COUNT"
        fi
        
        if [ -d "${ENHANCED_OUTPUT}/.cegar_cache" ]; then
            CEGAR_COUNT=$(ls "${ENHANCED_OUTPUT}/.cegar_cache"/*.json 2>/dev/null | wc -l)
            echo "CEGAR缓存数: $CEGAR_COUNT"
        fi
        echo ""
    else
        echo "ChatAFL-Enhanced未生成统计数据"
        echo ""
    fi
    
    echo "========== 对比分析 =========="
    if [ -f "${CHATAFL_OUTPUT}/fuzzer_stats" ] && [ -f "${ENHANCED_OUTPUT}/fuzzer_stats" ]; then
        CHATAFL_EXECS=$(grep "execs_done" "${CHATAFL_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        ENHANCED_EXECS=$(grep "execs_done" "${ENHANCED_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        CHATAFL_PATHS=$(grep "paths_total" "${CHATAFL_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        ENHANCED_PATHS=$(grep "paths_total" "${ENHANCED_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        
        echo "执行数对比: ChatAFL=$CHATAFL_EXECS, Enhanced=$ENHANCED_EXECS"
        echo "路径数对比: ChatAFL=$CHATAFL_PATHS, Enhanced=$ENHANCED_PATHS"
        
        if [ "$ENHANCED_PATHS" -gt "$CHATAFL_PATHS" ]; then
            IMPROVEMENT=$(awk "BEGIN {printf \"%.2f\", ($ENHANCED_PATHS - $CHATAFL_PATHS) * 100.0 / $CHATAFL_PATHS}")
            echo "Enhanced路径发现提升: +${IMPROVEMENT}%"
        fi
    fi
    
} > "$COMPARISON_LOG"

cat "$COMPARISON_LOG"

print_success "完成! 结果保存在: $COMPARISON_DIR"
echo ""
echo "查看完整报告: cat $COMPARISON_LOG"
echo "查看ChatAFL日志: cat $CHATAFL_LOG"
echo "查看Enhanced日志: cat $ENHANCED_LOG"
echo "查看ChatAFL输出: ls -la $CHATAFL_OUTPUT"
echo "查看Enhanced输出: ls -la $ENHANCED_OUTPUT"
