#!/bin/bash
#
# ChatAFL-Opt Docker 快速运行脚本
# 使用方法: ./docker-run.sh [模式] [参数]
#

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印带颜色的信息
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# 检查 Docker 是否安装
check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker 未安装。请先安装 Docker: https://docs.docker.com/get-docker/"
    fi
    info "Docker 版本: $(docker --version)"
}

# 检查环境变量
check_env() {
    if [ -z "$OPENAI_API_KEY" ]; then
        warn "未设置 OPENAI_API_KEY 环境变量"
        read -p "请输入您的 OpenAI API Key: " api_key
        export OPENAI_API_KEY="$api_key"
    fi
}

# 构建镜像
build_image() {
    info "构建 ChatAFL-Opt Docker 镜像..."
    docker build -t chatafl-opt:latest . || error "镜像构建失败"
    info "镜像构建成功"
}

# 准备目录
prepare_dirs() {
    mkdir -p seeds results targets
    info "创建目录: seeds/, results/, targets/"
}

# 运行交互式容器
run_interactive() {
    info "启动交互式容器..."
    docker run -it --rm \
        --name chatafl-opt-interactive \
        -e KEY="$OPENAI_API_KEY" \
        -v "$(pwd)/seeds:/opt/in" \
        -v "$(pwd)/results:/opt/out" \
        -v "$(pwd)/targets:/opt/targets" \
        chatafl-opt:latest \
        bash
}

# 运行后台容器
run_daemon() {
    local protocol=${1:-FTP}
    local target=${2:-tcp://127.0.0.1/21}
    
    info "启动后台模糊测试容器..."
    info "协议: $protocol, 目标: $target"
    
    docker run -d \
        --name chatafl-opt-fuzzer \
        -e KEY="$OPENAI_API_KEY" \
        -v "$(pwd)/seeds:/opt/in" \
        -v "$(pwd)/results:/opt/out" \
        -v "$(pwd)/targets:/opt/targets" \
        --network host \
        chatafl-opt:latest \
        ./afl-fuzz -i /opt/in -o /opt/out -N "$target" -P "$protocol" -- /bin/true
    
    info "容器已启动，ID: $(docker ps -lq)"
    info "查看日志: docker logs -f chatafl-opt-fuzzer"
    info "停止容器: docker stop chatafl-opt-fuzzer"
}

# 使用 Docker Compose
run_compose() {
    check_env
    info "使用 Docker Compose 启动服务..."
    docker-compose up -d
    info "服务已启动"
    info "查看状态: docker-compose ps"
    info "查看日志: docker-compose logs -f"
    info "停止服务: docker-compose down"
}

# 查看结果
view_results() {
    if [ ! -d "results" ]; then
        warn "results/ 目录不存在"
        return
    fi
    
    info "=== 模糊测试统计 ==="
    if [ -f "results/statistics.txt" ]; then
        cat results/statistics.txt
    fi
    
    info "\n=== LLM 假设 ==="
    if [ -f "results/hypotheses.json" ]; then
        if command -v jq &> /dev/null; then
            cat results/hypotheses.json | jq '.hypotheses[] | {message_type, revision, verified}'
        else
            cat results/hypotheses.json
        fi
    fi
    
    info "\n=== 状态树 ==="
    if [ -f "results/state_tree.dot" ]; then
        if command -v dot &> /dev/null; then
            dot -Tpng results/state_tree.dot -o results/state_tree.png
            info "状态树已生成: results/state_tree.png"
        else
            warn "未安装 Graphviz，无法生成状态树图片"
        fi
    fi
}

# 清理容器和卷
cleanup() {
    info "清理 Docker 资源..."
    docker-compose down -v 2>/dev/null || true
    docker stop chatafl-opt-fuzzer 2>/dev/null || true
    docker rm chatafl-opt-fuzzer 2>/dev/null || true
    docker stop chatafl-opt-interactive 2>/dev/null || true
    docker rm chatafl-opt-interactive 2>/dev/null || true
    info "清理完成"
}

# 显示帮助信息
show_help() {
    cat << EOF
ChatAFL-Opt Docker 快速运行脚本

使用方法:
  $0 [命令] [参数]

命令:
  build       构建 Docker 镜像
  interactive 启动交互式容器（默认）
  daemon      启动后台模糊测试容器
              用法: $0 daemon [协议] [目标]
              示例: $0 daemon FTP tcp://127.0.0.1/21
  compose     使用 Docker Compose 启动
  results     查看测试结果
  cleanup     清理所有容器和卷
  help        显示此帮助信息

环境变量:
  OPENAI_API_KEY  OpenAI API 密钥（必需）

示例:
  # 构建镜像
  $0 build

  # 启动交互式容器
  $0 interactive

  # 后台运行 FTP 模糊测试
  export OPENAI_API_KEY="sk-xxxxx"
  $0 daemon FTP tcp://127.0.0.1/21

  # 使用 Docker Compose
  $0 compose

  # 查看结果
  $0 results

  # 清理
  $0 cleanup

EOF
}

# 主函数
main() {
    check_docker
    
    case "${1:-interactive}" in
        build)
            build_image
            ;;
        interactive)
            check_env
            prepare_dirs
            run_interactive
            ;;
        daemon)
            check_env
            prepare_dirs
            run_daemon "${2:-FTP}" "${3:-tcp://127.0.0.1/21}"
            ;;
        compose)
            prepare_dirs
            run_compose
            ;;
        results)
            view_results
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "未知命令: $1\n使用 '$0 help' 查看帮助"
            ;;
    esac
}

main "$@"
