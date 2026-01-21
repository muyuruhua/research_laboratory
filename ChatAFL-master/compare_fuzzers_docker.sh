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

# 验证时间参数是否为正整数
if ! [[ "$TIMEOUT_MINUTES" =~ ^[0-9]+$ ]]; then
    echo "错误: 时间参数必须是正整数（分钟）"
    echo "用法: $0 <TARGET> <PROTOCOL> <TIMEOUT_MINUTES>"
    echo "示例: $0 LightFTP FTP 60"
    exit 1
fi

TIMEOUT_SECONDS=$((TIMEOUT_MINUTES * 60))

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
COMPARISON_DIR="$PROJECT_ROOT/comparison_results/${TARGET}_${TIMESTAMP}"

# 确保目录唯一性
COUNTER=1
while [ -d "$COMPARISON_DIR" ]; do
    COMPARISON_DIR="$PROJECT_ROOT/comparison_results/${TARGET}_${TIMESTAMP}_${COUNTER}"
    COUNTER=$((COUNTER + 1))
done

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
        CONTAINER_WORKDIR="/home/ubuntu/experiments/bftpd"
        CONTAINER_TARGET="./bftpd"
        TARGET_ARGS="-c /home/ubuntu/experiments/basic.conf -D"
        SEED_DIR="/home/ubuntu/experiments/in-ftp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/clean"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 15000+ -N tcp://127.0.0.1/21 -c $CLEAN_SCRIPT"
        ;;
    ProFTPD|proftpd)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/proftpd"
        CONTAINER_TARGET="./proftpd"
        TARGET_ARGS="-n -c /home/ubuntu/experiments/basic.conf"
        SEED_DIR="/home/ubuntu/experiments/in-ftp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/clean"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 15000+ -N tcp://127.0.0.1/21 -c $CLEAN_SCRIPT"
        ;;
    PureFTPD|pureftpd)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/pure-ftpd"
        CONTAINER_TARGET="src/pure-ftpd"
        TARGET_ARGS="-A"
        SEED_DIR="/home/ubuntu/experiments/in-ftp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/clean"
        AFL_OPTS="-d -P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 15000+ -N tcp://127.0.0.1/21 -c $CLEAN_SCRIPT"
        ;;
    Live555|live555)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/live/testProgs"
        CONTAINER_TARGET="./testOnDemandRTSPServer"
        TARGET_ARGS="8554"
        SEED_DIR="/home/ubuntu/experiments/in-rtsp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/kill-server"
        AFL_OPTS="-d -P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t 15000+ -N tcp://127.0.0.1/8554 -c $CLEAN_SCRIPT"
        ;;
    Exim|exim)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/exim"
        CONTAINER_TARGET="/usr/exim/bin/exim"
        TARGET_ARGS="-bdf -q15m"
        SEED_DIR="/home/ubuntu/experiments/in-smtp"
        CLEAN_SCRIPT="/home/ubuntu/experiments/clean"
        AFL_OPTS="-d -P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t 30000+ -N tcp://127.0.0.1/25 -c $CLEAN_SCRIPT"
        ;;
    Kamailio|kamailio)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/kamailio"
        CONTAINER_TARGET="./src/kamailio"
        TARGET_ARGS="-f /home/ubuntu/experiments/kamailio-basic.cfg -L src/modules -Y runtime_dir -n 1 -D -E"
        SEED_DIR="/home/ubuntu/experiments/in-sip"
        CLEAN_SCRIPT="/home/ubuntu/experiments/run_pjsip"
        AFL_OPTS="-d -P SIP -D 10000 -q 3 -s 3 -E -K -m none -t 15000+ -N udp://127.0.0.1/5060 -c $CLEAN_SCRIPT"
        ;;
    forked-daapd|Forked-daapd)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/forked-daapd"
        CONTAINER_TARGET="./forked-daapd"
        TARGET_ARGS="-f /home/ubuntu/experiments/basic.conf"
        SEED_DIR="/home/ubuntu/experiments/in-daap"
        CLEAN_SCRIPT="/home/ubuntu/experiments/clean"
        AFL_OPTS="-d -P DAAP -D 10000 -q 3 -s 3 -E -K -m none -t 15000+ -N tcp://127.0.0.1/3689 -c $CLEAN_SCRIPT"
        ;;
    Lighttpd1|lighttpd1)
        CONTAINER_WORKDIR="/home/ubuntu/experiments/lighttpd1.4"
        CONTAINER_TARGET="./src/lighttpd"
        TARGET_ARGS="-f /home/ubuntu/experiments/basic.conf -D"
        SEED_DIR="/home/ubuntu/experiments/in-http"
        CLEAN_SCRIPT="/home/ubuntu/experiments/clean"
        AFL_OPTS="-d -P HTTP -D 10000 -q 3 -s 3 -E -K -m none -t 15000+ -N tcp://127.0.0.1/8888 -c $CLEAN_SCRIPT"
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

# Kamailio需要特殊的环境变量
if [[ "$TARGET" == "Kamailio" || "$TARGET" == "kamailio" ]]; then
    ENV_VARS="-e KAMAILIO_MODULES=src/modules -e KAMAILIO_RUNTIME_DIR=runtime_dir"
else
    ENV_VARS=""
fi

# 运行ChatAFL容器
docker run -d \
    --name "chatafl_${TARGET}_${TIMESTAMP}" \
    -v "${CHATAFL_OUTPUT}:/home/ubuntu/output" \
    $ENV_VARS \
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

# Enhanced版本使用相同的AFL选项（FTP协议已经使用15秒超时）
ENHANCED_AFL_OPTS="$AFL_OPTS"

# 运行ChatAFL-Enhanced容器
docker run -d \
    --name "enhanced_${TARGET}_${TIMESTAMP}" \
    -v "${ENHANCED_OUTPUT}:/home/ubuntu/output" \
    $ENV_VARS \
    -e CHATAFL_ENHANCED=1 \
    "$DOCKER_IMAGE" \
    bash -c "cd $CONTAINER_WORKDIR && timeout ${TIMEOUT_SECONDS}s /home/ubuntu/chatafl-enhanced/afl-fuzz -i $SEED_DIR -o /home/ubuntu/output $ENHANCED_AFL_OPTS -- $CONTAINER_TARGET $TARGET_ARGS" \
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
        CHATAFL_EXECS=$(sudo grep "execs_done" "${CHATAFL_OUTPUT}/fuzzer_stats" 2>/dev/null | awk '{print $3}' || echo "0")
    else
        CHATAFL_EXECS="启动中..."
    fi
    
    if [ -f "${ENHANCED_OUTPUT}/fuzzer_stats" ]; then
        ENHANCED_EXECS=$(sudo grep "execs_done" "${ENHANCED_OUTPUT}/fuzzer_stats" 2>/dev/null | awk '{print $3}' || echo "0")
    else
        ENHANCED_EXECS="启动中..."
    fi
    
    printf "\r剩余时间: %02d:%02d | ChatAFL执行数: %s | Enhanced执行数: %s     " \
        $((REMAINING / 60)) $((REMAINING % 60)) "$CHATAFL_EXECS" "$ENHANCED_EXECS"
    
    sleep 10
done

print_header "Collecting logs"
docker logs "$CHATAFL_CONTAINER" > "$CHATAFL_LOG" 2>&1
docker logs "$ENHANCED_CONTAINER" > "$ENHANCED_LOG" 2>&1
print_success "Logs saved"

print_info "Cleaning up containers..."
docker rm "$CHATAFL_CONTAINER" "$ENHANCED_CONTAINER" 2>/dev/null
print_success "Containers cleaned up"

print_header "生成对比报告"

COMPARISON_LOG="${COMPARISON_DIR}/report.txt"

{
    echo "===== ChatAFL vs ChatAFL-Enhanced 对比报告 ====="
    echo "目标: $TARGET ($PROTOCOL), 时长: $TIMEOUT_MINUTES分钟"
    echo "时间: $(date)"
    echo ""
    
    if [ -f "${CHATAFL_OUTPUT}/fuzzer_stats" ]; then
        echo "========== ChatAFL 统计 =========="
        sudo grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|unique_hangs|bitmap_cvg|last_path" "${CHATAFL_OUTPUT}/fuzzer_stats"
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
        sudo grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|unique_hangs|bitmap_cvg|last_path" "${ENHANCED_OUTPUT}/fuzzer_stats"
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
        CHATAFL_EXECS=$(sudo grep "execs_done" "${CHATAFL_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        ENHANCED_EXECS=$(sudo grep "execs_done" "${ENHANCED_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        CHATAFL_PATHS=$(sudo grep "paths_total" "${CHATAFL_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        ENHANCED_PATHS=$(sudo grep "paths_total" "${ENHANCED_OUTPUT}/fuzzer_stats" | awk '{print $3}')
        
        echo "执行数对比: ChatAFL=$CHATAFL_EXECS, Enhanced=$ENHANCED_EXECS"
        echo "路径数对比: ChatAFL=$CHATAFL_PATHS, Enhanced=$ENHANCED_PATHS"
        
        if [ "$ENHANCED_PATHS" -gt "$CHATAFL_PATHS" ]; then
            IMPROVEMENT=$(awk "BEGIN {printf \"%.2f\", ($ENHANCED_PATHS - $CHATAFL_PATHS) * 100.0 / $CHATAFL_PATHS}")
            echo "Enhanced路径发现提升: +${IMPROVEMENT}%"
        fi
    fi
    
} > "$COMPARISON_LOG"

cat "$COMPARISON_LOG"

print_success "Complete! Results saved to: $COMPARISON_DIR"
echo ""
echo "查看完整报告: cat $COMPARISON_LOG"
echo "查看ChatAFL日志: cat $CHATAFL_LOG"
echo "查看Enhanced日志: cat $ENHANCED_LOG"
echo "查看ChatAFL输出: ls -la $CHATAFL_OUTPUT"
echo "查看Enhanced输出: ls -la $ENHANCED_OUTPUT"
