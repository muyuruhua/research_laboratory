#!/bin/bash
#
# ChatAFL-Opt 示例：使用 Docker 测试 LightFTP
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== ChatAFL-Opt Docker 示例：LightFTP 模糊测试 ==="

# 1. 检查依赖
if ! command -v docker &> /dev/null; then
    echo "错误: 未安装 Docker"
    exit 1
fi

# 2. 设置 API Key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "请设置 OPENAI_API_KEY 环境变量"
    read -p "输入您的 API Key: " api_key
    export OPENAI_API_KEY="$api_key"
fi

# 3. 准备种子文件
echo "[1/5] 准备种子文件..."
mkdir -p seeds
cat > seeds/ftp_login.txt << 'EOF'
USER anonymous
PASS test@example.com
QUIT
EOF

cat > seeds/ftp_commands.txt << 'EOF'
USER admin
PASS 12345
PWD
LIST
CWD /tmp
QUIT
EOF

echo "创建了 2 个种子文件"

# 4. 构建镜像
echo "[2/5] 构建 ChatAFL-Opt 镜像..."
docker build -t chatafl-opt:latest .

# 5. 启动 LightFTP 服务（模拟目标）
echo "[3/5] 启动 LightFTP 目标服务..."
docker run -d \
    --name lightftp-target \
    --network host \
    ubuntu:18.04 \
    bash -c "apt-get update && apt-get install -y vsftpd && service vsftpd start && tail -f /dev/null"

sleep 3

# 6. 运行模糊测试（限时 5 分钟）
echo "[4/5] 启动 ChatAFL-Opt 模糊测试（限时 5 分钟）..."
docker run -it --rm \
    --name chatafl-fuzzer \
    --network host \
    -e KEY="$OPENAI_API_KEY" \
    -v "$(pwd)/seeds:/opt/in" \
    -v "$(pwd)/results:/opt/out" \
    chatafl-opt:latest \
    timeout 300 ./afl-fuzz \
        -i /opt/in \
        -o /opt/out \
        -N tcp://127.0.0.1/21 \
        -P FTP \
        -t 5000 \
        -- /bin/true

# 7. 查看结果
echo "[5/5] 查看测试结果..."
if [ -f "results/statistics.txt" ]; then
    echo "=== 统计信息 ==="
    cat results/statistics.txt
fi

if [ -f "results/hypotheses.json" ]; then
    echo -e "\n=== LLM 假设 ==="
    cat results/hypotheses.json
fi

# 8. 清理
echo -e "\n=== 清理容器 ==="
docker stop lightftp-target && docker rm lightftp-target

echo -e "\n完成！结果保存在 results/ 目录中"
echo "查看状态树: dot -Tpng results/state_tree.dot -o results/state_tree.png"
