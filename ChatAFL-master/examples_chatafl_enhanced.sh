#!/bin/bash

#
# ChatAFL-Enhanced 使用示例
# 演示如何使用 ChatAFL-Enhanced 进行模糊测试
#

set -e

echo "=========================================="
echo " ChatAFL-Enhanced 使用示例"
echo "=========================================="
echo

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 示例函数
example() {
    echo -e "${BLUE}示例 $1:${NC} $2"
    echo -e "${YELLOW}命令:${NC} $3"
    echo
}

# 基础示例
echo "=========================================="
echo " 基础使用"
echo "=========================================="
echo

example 1 "快速测试 LightFTP (1个容器, 10分钟)" \
    "./run.sh 1 10 lightftp chatafl-enhanced"

example 2 "标准测试 Kamailio (5个容器, 60分钟)" \
    "./run.sh 5 60 kamailio chatafl-enhanced"

example 3 "长期测试 Live555 (5个容器, 24小时)" \
    "./run.sh 5 1440 live555 chatafl-enhanced"

# 比较示例
echo "=========================================="
echo " 对比测试"
echo "=========================================="
echo

example 4 "对比 ChatAFL vs ChatAFL-Enhanced" \
    "./run.sh 3 60 kamailio chatafl &
./run.sh 3 60 kamailio chatafl-enhanced &
wait"

example 5 "对比所有 ChatAFL 变体" \
    "./run.sh 3 60 bftpd chatafl &
./run.sh 3 60 bftpd chatafl-cl1 &
./run.sh 3 60 bftpd chatafl-cl2 &
./run.sh 3 60 bftpd chatafl-enhanced &
wait"

# 高级示例
echo "=========================================="
echo " 高级使用"
echo "=========================================="
echo

example 6 "使用环境变量自定义配置" \
    "export NUM_CONTAINERS=10
export TIMEOUT=7200
export SKIPCOUNT=5
export TEST_TIMEOUT=10000
./run.sh 10 120 proftpd chatafl-enhanced"

example 7 "直接编译并运行（不使用Docker）" \
    "cd ChatAFL-Enhanced
make clean all CHATAFL_ENHANCED=1
./afl-fuzz -i in-ftp -o out-ftp -P FTP -D 10000 -q 3 -s 3 -E -K -- /path/to/ftpd"

example 8 "仅编译基础模式（兼容 ChatAFL）" \
    "cd ChatAFL-Enhanced
make clean all
# 此时 afl-fuzz 的行为与 ChatAFL 完全相同"

# 结果分析示例
echo "=========================================="
echo " 结果分析"
echo "=========================================="
echo

example 9 "查看覆盖率统计" \
    "cd benchmark/results-kamailio
tar -xzf out-kamailio-chatafl_enhanced_1.tar.gz
cat out-kamailio-chatafl_enhanced/cov_over_time.csv"

example 10 "查看发现的崩溃" \
    "cd benchmark/results-kamailio/out-kamailio-chatafl_enhanced
ls -lh crashes/
ls -lh queue/"

example 11 "查看 HTML 覆盖率报告" \
    "cd benchmark/results-kamailio/out-kamailio-chatafl_enhanced/cov_html
# 在浏览器中打开 index.html"

# 故障排除示例
echo "=========================================="
echo " 故障排除"
echo "=========================================="
echo

example 12 "验证配置" \
    "chmod +x verify_chatafl_enhanced.sh
./verify_chatafl_enhanced.sh"

example 13 "检查 Docker 容器状态" \
    "docker ps -a | grep kamailio
docker logs <container_id>"

example 14 "清理并重新构建" \
    "cd ChatAFL-Enhanced
make clean
make CHATAFL_ENHANCED=1 2>&1 | tee build.log"

# 所有目标示例
echo "=========================================="
echo " 支持的目标"
echo "=========================================="
echo

echo -e "${GREEN}FTP 协议:${NC}"
echo "  - lightftp   : ./run.sh 3 30 lightftp chatafl-enhanced"
echo "  - bftpd      : ./run.sh 3 30 bftpd chatafl-enhanced"
echo "  - proftpd    : ./run.sh 3 30 proftpd chatafl-enhanced"
echo "  - pure-ftpd  : ./run.sh 3 30 pure-ftpd chatafl-enhanced"
echo

echo -e "${GREEN}其他协议:${NC}"
echo "  - exim       (SMTP) : ./run.sh 3 30 exim chatafl-enhanced"
echo "  - live555    (RTSP) : ./run.sh 3 30 live555 chatafl-enhanced"
echo "  - kamailio   (SIP)  : ./run.sh 3 30 kamailio chatafl-enhanced"
echo "  - forked-daapd (DAAP) : ./run.sh 3 30 forked-daapd chatafl-enhanced"
echo "  - lighttpd1  (HTTP) : ./run.sh 3 30 lighttpd1 chatafl-enhanced"
echo

# 性能提示
echo "=========================================="
echo " 性能优化提示"
echo "=========================================="
echo

echo -e "${YELLOW}1. 容器数量:${NC} 根据 CPU 核心数调整"
echo "   - 8核: NUM_CONTAINERS=6"
echo "   - 16核: NUM_CONTAINERS=12"
echo

echo -e "${YELLOW}2. 超时时间:${NC} 根据目标复杂度调整"
echo "   - 简单目标 (LightFTP): 30-60分钟"
echo "   - 复杂目标 (Kamailio): 120-1440分钟"
echo

echo -e "${YELLOW}3. 测试超时:${NC} 调整单个测试用例超时"
echo "   - 快速响应: TEST_TIMEOUT=1000"
echo "   - 慢速响应: TEST_TIMEOUT=10000"
echo

# 完成
echo "=========================================="
echo " 更多信息"
echo "=========================================="
echo

echo "详细文档:"
echo "  - ChatAFL-Enhanced/README-ENHANCED.md"
echo "  - QUICKSTART-ENHANCED.md"
echo "  - CHATAFL_ENHANCED_ADAPTATION_REPORT.md"
echo

echo -e "${GREEN}准备开始？运行:${NC}"
echo "  ./run.sh 5 10 kamailio chatafl-enhanced"
echo
