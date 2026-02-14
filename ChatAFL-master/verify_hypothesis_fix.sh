#!/bin/bash
# 验证 Hypothesis 修复的脚本

echo "=== Hypothesis Fix Verification ==="
echo ""

# 1. 检查修复的代码是否已经复制到所有目标
echo "[1] 检查修复后的文件是否存在..."
for target in LightFTP BFTPD; do
    file="/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark/subjects/FTP/$target/chatafl-opt/grammar-hypothesis.c"
    if [ -f "$file" ]; then
        # 检查是否包含修复的关键代码
        if grep -q "if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset)" "$file"; then
            echo "  ✓ $target: 修复已应用"
        else
            echo "  ✗ $target: 修复未应用"
        fi
    else
        echo "  ✗ $target: 文件不存在"
    fi
done
echo ""

# 2. 检查镜像是否构建成功
echo "[2] 检查 Docker 镜像..."
for image in lightftp bftpd; do
    if docker images | grep -q "^$image "; then
        echo "  ✓ $image 镜像存在"
    else
        echo "  ✗ $image 镜像不存在"
    fi
done
echo ""

# 3. 启动测试容器验证
echo "[3] 启动测试容器验证编译..."
echo "测试 lightftp 镜像中的 chatafl-opt..."
docker run --rm lightftp /home/ubuntu/chatafl-opt/afl-fuzz -h 2>&1 | head -3

echo ""
echo "=== 下一步 ==="
echo "运行测试: cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master"
echo "           sudo -E ./run.sh 1 10 lightftp chatafl-opt"
echo ""
echo "监控容器: docker ps  # 获取容器ID"
echo "           docker logs -f <container_id> | grep -E 'hypothesis|buffer overflow|Segmentation'"
