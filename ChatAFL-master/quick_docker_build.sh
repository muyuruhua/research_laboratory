#!/bin/bash
# quick_docker_build.sh - 快速Docker构建（假设fuzzer已复制）

cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

echo "=========================================="
echo " Docker构建实时监控"
echo "=========================================="
echo ""

# 检查fuzzers是否已复制
if [ ! -d "benchmark/subjects/FTP/LightFTP/chatafl-enhanced" ]; then
    echo "正在复制fuzzers到benchmark目录..."
    for subject in ./benchmark/subjects/*/*; do
      if [ -d "$subject" ]; then
        rm -rf $subject/aflnet $subject/chatafl* 2>/dev/null
        [ -d "aflnet-master" ] && cp -r aflnet-master $subject/aflnet || cp -r aflnet $subject/aflnet
        cp -r ChatAFL $subject/chatafl
        cp -r ChatAFL-CL1 $subject/chatafl-cl1
        cp -r ChatAFL-CL2 $subject/chatafl-cl2
        cp -r ChatAFL-Enhanced $subject/chatafl-enhanced
      fi
    done
    echo "✓ 复制完成"
fi

# 备份并删除旧镜像
docker tag lightftp:latest lightftp:old 2>/dev/null || true
docker rmi lightftp:latest 2>/dev/null || true

# 构建镜像（实时显示）
cd benchmark/subjects/FTP/LightFTP
echo ""
echo "开始构建Docker镜像（实时显示）..."
echo "--------------------------------------"
docker build -t lightftp --build-arg MAKE_OPT="-j$(nproc)" .
