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
    echo "使用方法: $0 <TARGET> <PROTOCOL> <TIMEOUT_MINUTES> [NUM_RUNS]"
    echo ""
    echo "参数:"
    echo "  TARGET           - 目标程序名称"
    echo "  PROTOCOL         - 协议类型"
    echo "  TIMEOUT_MINUTES  - 测试时长(分钟)"
    echo "  NUM_RUNS         - 并行运行次数 (可选, 默认1, 最大10)"
    echo ""
    echo "示例:"
    echo "  $0 LightFTP FTP 60        # 单次运行"
    echo "  $0 LightFTP FTP 60 5      # 并行5次运行"
    echo "  $0 Live555 RTSP 120 3     # 并行3次运行,每次120分钟"
    echo ""
    echo "支持的目标: LightFTP, BFTPD, ProFTPD, PureFTPD, Live555, Exim, Kamailio, forked-daapd, Lighttpd1"
    exit 1
}

[ $# -lt 3 ] && usage

TARGET=$1
PROTOCOL=$2
TIMEOUT_MINUTES=$3
NUM_RUNS=${4:-1}  # 默认1次运行

# 验证运行次数
if ! [[ "$NUM_RUNS" =~ ^[0-9]+$ ]] || [ "$NUM_RUNS" -lt 1 ] || [ "$NUM_RUNS" -gt 10 ]; then
    echo "错误: 运行次数必须是1-10之间的整数"
    echo "当前值: $NUM_RUNS"
    exit 1
fi

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

# 创建多次运行的目录结构
mkdir -p "$COMPARISON_DIR"

# 为每次运行创建子目录
for i in $(seq 1 $NUM_RUNS); do
    mkdir -p "$COMPARISON_DIR/run_${i}"/{chatafl,chatafl-enhanced}
done

# 创建汇总目录
mkdir -p "$COMPARISON_DIR/summary"
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

print_header "对比测试: ChatAFL vs ChatAFL-Enhanced (${NUM_RUNS}次运行)"
echo "目标: $TARGET ($PROTOCOL), 时长: $TIMEOUT_MINUTES 分钟"
echo "Docker镜像: $DOCKER_IMAGE"
echo "运行次数: $NUM_RUNS"
echo "输出目录: $COMPARISON_DIR"
echo ""

# Kamailio需要特殊的环境变量
if [[ "$TARGET" == "Kamailio" || "$TARGET" == "kamailio" ]]; then
    ENV_VARS="-e KAMAILIO_MODULES=src/modules -e KAMAILIO_RUNTIME_DIR=runtime_dir"
else
    ENV_VARS=""
fi

# Enhanced环境变量
ENHANCED_ENV="-e CHATAFL_ENHANCED=1 \
-e CHATAFL_CEGAR_ENABLE=1 \
-e CHATAFL_CEGAR_INTERVAL=1000 \
-e CHATAFL_LLM_BUDGET_HOURLY=100 \
-e CHATAFL_CEGAR_MAX_RETRIES=3 \
-e CHATAFL_CEGAR_FAST_FAIL=1 \
-e CHATAFL_CEGAR_MONITOR=1 \
-e CHATAFL_VERIFIER_LOG=1 \
-e CHATAFL_VERIFIER_DEBUG=1 \
-e CHATAFL_PLATEAU_THRESHOLD=100 \
-e CHATAFL_USE_EVENT_BUS=1"

# 启动所有容器
declare -a CHATAFL_CONTAINERS
declare -a ENHANCED_CONTAINERS

print_header "启动 ${NUM_RUNS} 组并行测试容器"

for i in $(seq 1 $NUM_RUNS); do
    RUN_CHATAFL_OUTPUT="${COMPARISON_DIR}/run_${i}/chatafl"
    RUN_ENHANCED_OUTPUT="${COMPARISON_DIR}/run_${i}/chatafl-enhanced"
    
    CHATAFL_NAME="chatafl_${TARGET}_${TIMESTAMP}_run_${i}"
    ENHANCED_NAME="enhanced_${TARGET}_${TIMESTAMP}_run_${i}"
    
    echo "启动第 ${i} 组容器..."
    
    # 启动ChatAFL容器
    docker run -d \
        --name "$CHATAFL_NAME" \
        -v "${RUN_CHATAFL_OUTPUT}:/home/ubuntu/output" \
        $ENV_VARS \
        "$DOCKER_IMAGE" \
        bash -c "cd $CONTAINER_WORKDIR && timeout ${TIMEOUT_SECONDS}s /home/ubuntu/chatafl/afl-fuzz -i $SEED_DIR -o /home/ubuntu/output $AFL_OPTS -- $CONTAINER_TARGET $TARGET_ARGS" \
        > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        CHATAFL_CONTAINERS+=("$CHATAFL_NAME")
        echo "  ✓ ChatAFL容器 ${i} 已启动: $CHATAFL_NAME"
    else
        print_error "ChatAFL容器 ${i} 启动失败"
        # 清理已启动的容器
        for container in "${CHATAFL_CONTAINERS[@]}" "${ENHANCED_CONTAINERS[@]}"; do
            docker stop "$container" 2>/dev/null
            docker rm "$container" 2>/dev/null
        done
        exit 1
    fi
    
    # 启动Enhanced容器
    docker run -d \
        --name "$ENHANCED_NAME" \
        -v "${RUN_ENHANCED_OUTPUT}:/home/ubuntu/output" \
        $ENV_VARS \
        $ENHANCED_ENV \
        "$DOCKER_IMAGE" \
        bash -c "cd $CONTAINER_WORKDIR && timeout ${TIMEOUT_SECONDS}s /home/ubuntu/chatafl-enhanced/afl-fuzz -i $SEED_DIR -o /home/ubuntu/output $AFL_OPTS -- $CONTAINER_TARGET $TARGET_ARGS" \
        > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        ENHANCED_CONTAINERS+=("$ENHANCED_NAME")
        echo "  ✓ Enhanced容器 ${i} 已启动: $ENHANCED_NAME"
    else
        print_error "Enhanced容器 ${i} 启动失败"
        # 清理已启动的容器
        for container in "${CHATAFL_CONTAINERS[@]}" "${ENHANCED_CONTAINERS[@]}"; do
            docker stop "$container" 2>/dev/null
            docker rm "$container" 2>/dev/null
        done
        exit 1
    fi
    
    sleep 2
done

print_success "所有 $((NUM_RUNS * 2)) 个容器已成功启动"

print_header "等待测试完成 ($TIMEOUT_MINUTES 分钟)"
echo "ChatAFL容器: ${CHATAFL_CONTAINERS[@]}"
echo "Enhanced容器: ${ENHANCED_CONTAINERS[@]}"
echo ""
echo "实时监控示例 (第1组):"
echo "  docker logs -f ${CHATAFL_CONTAINERS[0]}"
echo "  docker logs -f ${ENHANCED_CONTAINERS[0]}"
echo ""

# 显示进度并监控所有容器
START_TIME=$(date +%s)
while true; do
    RUNNING_COUNT=0
    for container in "${CHATAFL_CONTAINERS[@]}" "${ENHANCED_CONTAINERS[@]}"; do
        if docker ps -q -f name="$container" 2>/dev/null | grep -q .; then
            ((RUNNING_COUNT++))
        fi
    done
    
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    REMAINING=$((TIMEOUT_SECONDS - ELAPSED))
    
    if [ $RUNNING_COUNT -eq 0 ]; then
        echo ""
        print_success "所有容器都已完成"
        break
    fi
    
    if [ $REMAINING -le 0 ]; then
        echo ""
        print_info "超时，停止所有容器..."
        for container in "${CHATAFL_CONTAINERS[@]}" "${ENHANCED_CONTAINERS[@]}"; do
            docker stop "$container" 2>/dev/null
        done
        break
    fi
    
    # 统计总体执行数
    TOTAL_CHATAFL_EXECS=0
    TOTAL_ENHANCED_EXECS=0
    CHATAFL_READY=0
    ENHANCED_READY=0
    
    for i in $(seq 1 $NUM_RUNS); do
        CHATAFL_STATS="${COMPARISON_DIR}/run_${i}/chatafl/fuzzer_stats"
        ENHANCED_STATS="${COMPARISON_DIR}/run_${i}/chatafl-enhanced/fuzzer_stats"
        
        if [ -f "$CHATAFL_STATS" ]; then
            EXECS=$(sudo grep "execs_done" "$CHATAFL_STATS" 2>/dev/null | awk '{print $3}' || echo "0")
            TOTAL_CHATAFL_EXECS=$((TOTAL_CHATAFL_EXECS + EXECS))
            ((CHATAFL_READY++))
        fi
        
        if [ -f "$ENHANCED_STATS" ]; then
            EXECS=$(sudo grep "execs_done" "$ENHANCED_STATS" 2>/dev/null | awk '{print $3}' || echo "0")
            TOTAL_ENHANCED_EXECS=$((TOTAL_ENHANCED_EXECS + EXECS))
            ((ENHANCED_READY++))
        fi
    done
    
    printf "\r剩余: %02d:%02d | 运行中: %d/%d | ChatAFL总执行: %d (%d就绪) | Enhanced总执行: %d (%d就绪)     " \
        $((REMAINING / 60)) $((REMAINING % 60)) $RUNNING_COUNT $((NUM_RUNS * 2)) \
        $TOTAL_CHATAFL_EXECS $CHATAFL_READY $TOTAL_ENHANCED_EXECS $ENHANCED_READY
    
    sleep 10
done

print_header "收集所有日志"
for i in $(seq 1 $NUM_RUNS); do
    CHATAFL_LOG="${COMPARISON_DIR}/run_${i}/chatafl.log"
    ENHANCED_LOG="${COMPARISON_DIR}/run_${i}/enhanced.log"
    
    docker logs "${CHATAFL_CONTAINERS[$((i-1))]}" > "$CHATAFL_LOG" 2>&1
    docker logs "${ENHANCED_CONTAINERS[$((i-1))]}" > "$ENHANCED_LOG" 2>&1
done
print_success "所有日志已保存"

print_info "清理容器..."
for container in "${CHATAFL_CONTAINERS[@]}" "${ENHANCED_CONTAINERS[@]}"; do
    docker rm "$container" 2>/dev/null
done
print_success "容器已清理"

print_header "生成汇总报告"

SUMMARY_REPORT="${COMPARISON_DIR}/summary/report.txt"

{
    echo "===== ChatAFL vs ChatAFL-Enhanced 对比报告 ====="
    echo "目标: $TARGET ($PROTOCOL), 时长: $TIMEOUT_MINUTES分钟, 运行次数: $NUM_RUNS"
    echo "时间: $(date)"
    echo ""
    
    # 计算每次运行的结果
    declare -a CHATAFL_EXECS_ARRAY
    declare -a CHATAFL_PATHS_ARRAY
    declare -a ENHANCED_EXECS_ARRAY
    declare -a ENHANCED_PATHS_ARRAY
    
    echo "========== 各次运行详情 =========="
    for i in $(seq 1 $NUM_RUNS); do
        echo "--- 第 ${i} 次运行 ---"
        
        CHATAFL_STATS="${COMPARISON_DIR}/run_${i}/chatafl/fuzzer_stats"
        ENHANCED_STATS="${COMPARISON_DIR}/run_${i}/chatafl-enhanced/fuzzer_stats"
        
        if [ -f "$CHATAFL_STATS" ]; then
            echo "ChatAFL:"
            sudo grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|bitmap_cvg" "$CHATAFL_STATS" | sed 's/^/  /'
            
            EXECS=$(sudo grep "execs_done" "$CHATAFL_STATS" | awk '{print $3}')
            PATHS=$(sudo grep "paths_total" "$CHATAFL_STATS" | awk '{print $3}')
            CHATAFL_EXECS_ARRAY+=($EXECS)
            CHATAFL_PATHS_ARRAY+=($PATHS)
        else
            echo "ChatAFL: 未生成统计数据"
            CHATAFL_EXECS_ARRAY+=(0)
            CHATAFL_PATHS_ARRAY+=(0)
        fi
        
        if [ -f "$ENHANCED_STATS" ]; then
            echo "Enhanced:"
            sudo grep -E "execs_done|execs_per_sec|paths_total|unique_crashes|bitmap_cvg" "$ENHANCED_STATS" | sed 's/^/  /'
            
            EXECS=$(sudo grep "execs_done" "$ENHANCED_STATS" | awk '{print $3}')
            PATHS=$(sudo grep "paths_total" "$ENHANCED_STATS" | awk '{print $3}')
            ENHANCED_EXECS_ARRAY+=($EXECS)
            ENHANCED_PATHS_ARRAY+=($PATHS)
        else
            echo "Enhanced: 未生成统计数据"
            ENHANCED_EXECS_ARRAY+=(0)
            ENHANCED_PATHS_ARRAY+=(0)
        fi
        echo ""
    done
    
    echo "========== 平均统计 =========="
    
    # 计算平均值
    CHATAFL_EXECS_SUM=0
    CHATAFL_PATHS_SUM=0
    for val in "${CHATAFL_EXECS_ARRAY[@]}"; do
        CHATAFL_EXECS_SUM=$((CHATAFL_EXECS_SUM + val))
    done
    for val in "${CHATAFL_PATHS_ARRAY[@]}"; do
        CHATAFL_PATHS_SUM=$((CHATAFL_PATHS_SUM + val))
    done
    CHATAFL_EXECS_AVG=$((CHATAFL_EXECS_SUM / NUM_RUNS))
    CHATAFL_PATHS_AVG=$((CHATAFL_PATHS_SUM / NUM_RUNS))
    
    ENHANCED_EXECS_SUM=0
    ENHANCED_PATHS_SUM=0
    for val in "${ENHANCED_EXECS_ARRAY[@]}"; do
        ENHANCED_EXECS_SUM=$((ENHANCED_EXECS_SUM + val))
    done
    for val in "${ENHANCED_PATHS_ARRAY[@]}"; do
        ENHANCED_PATHS_SUM=$((ENHANCED_PATHS_SUM + val))
    done
    ENHANCED_EXECS_AVG=$((ENHANCED_EXECS_SUM / NUM_RUNS))
    ENHANCED_PATHS_AVG=$((ENHANCED_PATHS_SUM / NUM_RUNS))
    
    echo "ChatAFL 平均执行数: $CHATAFL_EXECS_AVG"
    echo "ChatAFL 平均路径数: $CHATAFL_PATHS_AVG"
    echo ""
    echo "Enhanced 平均执行数: $ENHANCED_EXECS_AVG"
    echo "Enhanced 平均路径数: $ENHANCED_PATHS_AVG"
    echo ""
    
    # 计算标准差（简化版本）
    CHATAFL_EXECS_SQSUM=0
    for val in "${CHATAFL_EXECS_ARRAY[@]}"; do
        DIFF=$((val - CHATAFL_EXECS_AVG))
        CHATAFL_EXECS_SQSUM=$((CHATAFL_EXECS_SQSUM + DIFF * DIFF))
    done
    CHATAFL_EXECS_STDDEV=$(echo "scale=2; sqrt($CHATAFL_EXECS_SQSUM / $NUM_RUNS)" | bc)
    
    ENHANCED_EXECS_SQSUM=0
    for val in "${ENHANCED_EXECS_ARRAY[@]}"; do
        DIFF=$((val - ENHANCED_EXECS_AVG))
        ENHANCED_EXECS_SQSUM=$((ENHANCED_EXECS_SQSUM + DIFF * DIFF))
    done
    ENHANCED_EXECS_STDDEV=$(echo "scale=2; sqrt($ENHANCED_EXECS_SQSUM / $NUM_RUNS)" | bc)
    
    echo "ChatAFL 执行数标准差: ±$CHATAFL_EXECS_STDDEV"
    echo "Enhanced 执行数标准差: ±$ENHANCED_EXECS_STDDEV"
    echo ""
    
    echo "========== 对比分析 =========="
    echo "执行数对比: ChatAFL=${CHATAFL_EXECS_AVG}±${CHATAFL_EXECS_STDDEV}, Enhanced=${ENHANCED_EXECS_AVG}±${ENHANCED_EXECS_STDDEV}"
    echo "路径数对比: ChatAFL=$CHATAFL_PATHS_AVG, Enhanced=$ENHANCED_PATHS_AVG"
    
    if [ "$ENHANCED_PATHS_AVG" -gt "$CHATAFL_PATHS_AVG" ]; then
        IMPROVEMENT=$(awk "BEGIN {printf \"%.2f\", ($ENHANCED_PATHS_AVG - $CHATAFL_PATHS_AVG) * 100.0 / $CHATAFL_PATHS_AVG}")
        echo "Enhanced路径发现平均提升: +${IMPROVEMENT}%"
    elif [ "$CHATAFL_PATHS_AVG" -gt "$ENHANCED_PATHS_AVG" ]; then
        DEGRADATION=$(awk "BEGIN {printf \"%.2f\", ($CHATAFL_PATHS_AVG - $ENHANCED_PATHS_AVG) * 100.0 / $CHATAFL_PATHS_AVG}")
        echo "Enhanced路径发现平均下降: -${DEGRADATION}%"
    else
        echo "路径发现无明显差异"
    fi
    
} > "$SUMMARY_REPORT"

cat "$SUMMARY_REPORT"

print_success "Complete! Results saved to: $COMPARISON_DIR"
echo ""
echo "查看汇总报告: cat ${SUMMARY_REPORT}"
echo "各次运行结果:"
for i in $(seq 1 $NUM_RUNS); do
    echo "  第${i}次: ${COMPARISON_DIR}/run_${i}/"
done
echo ""
echo "生成可视化图表:"
echo "  python3 visualize_comparison.py ${COMPARISON_DIR}"
