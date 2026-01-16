#!/bin/bash
# 开发模式快速同步脚本 - 将代码改动实时同步到容器并重新编译

set -e

CONTAINER_NAME="${CONTAINER_NAME:-chatafl-enhanced-dev}"
IMAGE_NAME="${IMAGE_NAME:-chatafl-enhanced:dev}"

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_usage() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  start    - 启动开发容器（挂载当前目录到容器）"
    echo "  sync     - 同步代码并在容器内重新编译"
    echo "  rebuild  - 仅重新编译（无需复制）"
    echo "  shell    - 进入容器bash"
    echo "  stop     - 停止开发容器"
    echo "  logs     - 查看容器日志"
    echo ""
    echo "环境变量:"
    echo "  CONTAINER_NAME - 容器名（默认: chatafl-enhanced-dev）"
    echo "  WATCH_MODE     - 设为1启用文件监控自动同步"
}

start_dev_container() {
    echo -e "${GREEN}[1/4] 检查容器状态...${NC}"
    
    # 检查容器是否已存在
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${YELLOW}容器 ${CONTAINER_NAME} 已存在${NC}"
        
        # 检查是否在运行
        if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            echo -e "${GREEN}容器正在运行中${NC}"
            return 0
        else
            echo -e "${YELLOW}启动已停止的容器...${NC}"
            docker start ${CONTAINER_NAME}
            return 0
        fi
    fi
    
    echo -e "${GREEN}[2/4] 检查Docker镜像...${NC}"
    
    # 检查镜像是否存在
    if ! docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}$"; then
        echo -e "${YELLOW}镜像 ${IMAGE_NAME} 不存在，开始构建...${NC}"
        
        # 获取当前目录
        CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        
        # 检查Dockerfile是否存在
        if [ ! -f "${CURRENT_DIR}/Dockerfile" ]; then
            echo -e "${RED}错误: 未找到 Dockerfile${NC}"
            echo -e "${YELLOW}请确保在 ChatAFL-Enhanced 目录下运行此脚本${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}[3/4] 构建Docker镜像（首次需要5-10分钟）...${NC}"
        docker build -t ${IMAGE_NAME} "${CURRENT_DIR}"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}错误: 镜像构建失败${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}✓ 镜像构建完成${NC}"
    else
        echo -e "${GREEN}✓ 镜像 ${IMAGE_NAME} 已存在${NC}"
    fi
    
    echo -e "${GREEN}[4/4] 创建开发容器（挂载代码目录）...${NC}"
    
    # 获取当前目录的绝对路径
    CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    docker run -d \
        --name ${CONTAINER_NAME} \
        --cap-add=SYS_PTRACE \
        -v "${CURRENT_DIR}:/opt/aflnet:rw" \
        -w /opt/aflnet \
        --entrypoint /bin/bash \
        ${IMAGE_NAME} \
        -c "tail -f /dev/null"
    
    echo -e "${GREEN}✓ 容器已启动，代码目录已挂载${NC}"
    echo -e "${YELLOW}提示: 现在修改宿主机代码会立即反映到容器中${NC}"
    echo -e "${YELLOW}运行 '$0 sync' 来重新编译${NC}"
}

sync_and_compile() {
    echo -e "${GREEN}[1/2] 检查容器状态...${NC}"
    
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${RED}错误: 容器 ${CONTAINER_NAME} 未运行${NC}"
        echo -e "${YELLOW}请先运行: $0 start${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[2/2] 在容器内重新编译...${NC}"
    
    # 记录开始时间
    START_TIME=$(date +%s)
    
    docker exec -it ${CONTAINER_NAME} bash -c "
        cd /opt/aflnet
        echo '→ 清理旧的编译文件...'
        make clean > /dev/null 2>&1
        
        echo '→ 重新编译 AFLNet + ChatAFL-Enhanced...'
        make -j\$(nproc) 2>&1 | grep -E '(error|warning|Compiling|Linking)' || true
        
        echo ''
        echo '✓ 编译完成'
        echo '→ 验证二进制文件...'
        ls -lh afl-fuzz afl-replay aflnet-replay 2>/dev/null || echo '警告: 某些二进制文件未生成'
        
        echo ''
        echo '→ 检查新增模块...'
        nm afl-fuzz 2>/dev/null | grep -c 'llm_cost' && echo '  ✓ llm-cost-tracker 模块已链接' || echo '  ✗ llm-cost-tracker 未找到'
        nm afl-fuzz 2>/dev/null | grep -c 'state_graph' && echo '  ✓ state-graph 模块已链接' || echo '  ✗ state-graph 未找到'
        nm afl-fuzz 2>/dev/null | grep -c 'plateau_breakthrough' && echo '  ✓ Plateau突破功能已链接' || echo '  ✗ Plateau突破未找到'
    "
    
    # 计算编译时间
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    echo -e "${GREEN}✓ 同步完成，耗时: ${DURATION}秒${NC}"
}

rebuild_only() {
    echo -e "${GREEN}快速重编译（无清理）...${NC}"
    
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${RED}错误: 容器 ${CONTAINER_NAME} 未运行${NC}"
        exit 1
    fi
    
    docker exec -it ${CONTAINER_NAME} bash -c "
        cd /opt/aflnet
        make -j\$(nproc) 2>&1 | tail -20
    "
    
    echo -e "${GREEN}✓ 快速编译完成${NC}"
}

enter_shell() {
    if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${RED}错误: 容器 ${CONTAINER_NAME} 未运行${NC}"
        echo -e "${YELLOW}请先运行: $0 start${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}进入容器 shell (exit 退出)...${NC}"
    docker exec -it ${CONTAINER_NAME} bash
}

stop_container() {
    echo -e "${YELLOW}停止开发容器...${NC}"
    docker stop ${CONTAINER_NAME} 2>/dev/null || echo "容器未运行"
    echo -e "${GREEN}✓ 容器已停止（数据已保留）${NC}"
    echo -e "${YELLOW}提示: 运行 '$0 start' 可恢复${NC}"
}

view_logs() {
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "${RED}错误: 容器 ${CONTAINER_NAME} 不存在${NC}"
        exit 1
    fi
    
    docker logs -f ${CONTAINER_NAME}
}

watch_mode() {
    echo -e "${GREEN}启动文件监控模式（自动同步）...${NC}"
    echo -e "${YELLOW}监控扩展名: .c .h .cc .cpp${NC}"
    echo -e "${YELLOW}按 Ctrl+C 停止监控${NC}"
    echo ""
    
    if ! command -v inotifywait &> /dev/null; then
        echo -e "${RED}错误: 需要安装 inotify-tools${NC}"
        echo "Ubuntu/Debian: sudo apt-get install inotify-tools"
        echo "CentOS/RHEL:   sudo yum install inotify-tools"
        exit 1
    fi
    
    CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    inotifywait -m -r -e modify,create,delete \
        --exclude '(\.o$|\.swp$|\.git|afl-fuzz$|afl-replay$)' \
        "${CURRENT_DIR}" | while read path action file; do
        
        # 只处理 C/C++ 源文件
        if [[ "$file" =~ \.(c|h|cc|cpp)$ ]]; then
            echo -e "${YELLOW}检测到变化: ${path}${file}${NC}"
            echo -e "${GREEN}触发重新编译...${NC}"
            rebuild_only
            echo ""
        fi
    done
}

# 主逻辑
case "${1:-}" in
    start)
        start_dev_container
        ;;
    sync)
        sync_and_compile
        ;;
    rebuild)
        rebuild_only
        ;;
    shell|bash)
        enter_shell
        ;;
    stop)
        stop_container
        ;;
    logs)
        view_logs
        ;;
    watch)
        watch_mode
        ;;
    *)
        print_usage
        exit 1
        ;;
esac
