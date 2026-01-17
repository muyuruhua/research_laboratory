#!/bin/bash
# complete_rebuild_docker.sh - 完整的Docker镜像重建流程（包含setup.sh）

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo " 完整Docker镜像重建流程"
echo "=========================================="
echo ""

# Step 1: 编译ChatAFL-Enhanced
echo -e "${BLUE}[1/4]${NC} 编译ChatAFL-Enhanced (使用-O3优化)..."
cd ChatAFL-Enhanced

echo "  → 清理旧构建..."
make clean > /dev/null 2>&1

echo "  → 编译Enhanced模块..."
make -f Makefile.enhanced clean > /dev/null 2>&1
make -f Makefile.enhanced integrated
if [ $? -ne 0 ]; then
    echo -e "${RED}✗${NC} Enhanced模块编译失败！"
    exit 1
fi

echo "  → 编译主二进制..."
make clean all
if [ $? -ne 0 ]; then
    echo -e "${RED}✗${NC} afl-fuzz编译失败！"
    exit 1
fi

cd ..
ENHANCED_SIZE=$(stat -c%s ChatAFL-Enhanced/afl-fuzz)
ENHANCED_TIME=$(stat -c%y ChatAFL-Enhanced/afl-fuzz | cut -d'.' -f1)
echo -e "${GREEN}✓${NC} Enhanced编译完成"
echo "    大小: $(numfmt --to=iec-i --suffix=B $ENHANCED_SIZE)"
echo "    时间: $ENHANCED_TIME"

# Step 2: 复制fuzzers到benchmark目录
echo ""
echo -e "${BLUE}[2/4]${NC} 复制fuzzers到benchmark目录..."
COPIED_COUNT=0
for subject in ./benchmark/subjects/*/*; do
  if [ -d "$subject" ]; then
    # 复制aflnet（检查目录名）
    rm -rf $subject/aflnet 2>/dev/null
    if [ -d "aflnet-master" ]; then
        cp -r aflnet-master $subject/aflnet
    elif [ -d "aflnet" ]; then
        cp -r aflnet $subject/aflnet
    fi
    
    # 复制各版本ChatAFL
    rm -rf $subject/chatafl 2>/dev/null
    cp -r ChatAFL $subject/chatafl
    
    rm -rf $subject/chatafl-cl1 2>/dev/null
    cp -r ChatAFL-CL1 $subject/chatafl-cl1
    
    rm -rf $subject/chatafl-cl2 2>/dev/null
    cp -r ChatAFL-CL2 $subject/chatafl-cl2
    
    rm -rf $subject/chatafl-enhanced 2>/dev/null
    cp -r ChatAFL-Enhanced $subject/chatafl-enhanced
    
    COPIED_COUNT=$((COPIED_COUNT + 1))
  fi
done
echo -e "${GREEN}✓${NC} 已复制到 $COPIED_COUNT 个目标"

# Step 3: 备份旧镜像
echo ""
echo -e "${BLUE}[3/4]${NC} 备份当前Docker镜像..."
if docker images | grep -q "^lightftp "; then
    docker tag lightftp:latest lightftp:backup-$(date +%Y%m%d-%H%M%S) 2>/dev/null || true
    docker rmi lightftp:latest 2>/dev/null || true
    echo -e "${GREEN}✓${NC} 旧镜像已备份并删除"
else
    echo "  → 无需备份（镜像不存在）"
fi

# Step 4: 重新构建Docker镜像
echo ""
echo -e "${BLUE}[4/4]${NC} 重新构建lightftp Docker镜像..."
echo ""
echo "构建参数:"
echo "  目标: LightFTP"
echo "  协议: FTP"
echo "  Dockerfile: benchmark/subjects/FTP/LightFTP/Dockerfile"
echo "  并发: -j$(nproc)"
echo ""
echo "预计耗时: 5-10分钟"
echo ""

cd benchmark/subjects/FTP/LightFTP

# 实时显示构建进度
docker build -t lightftp --build-arg MAKE_OPT="-j$(nproc)" . 2>&1 | tee /tmp/docker_build_full.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}=========================================="
    echo "✓ Docker镜像构建成功！"
    echo "==========================================${NC}"
    echo ""
    
    # 验证镜像
    echo "验证新镜像中的Enhanced版本..."
    DOCKER_TIME=$(docker run --rm lightftp stat -c%y /home/ubuntu/chatafl-enhanced/afl-fuzz 2>/dev/null | cut -d'.' -f1)
    DOCKER_SIZE=$(docker run --rm lightftp stat -c%s /home/ubuntu/chatafl-enhanced/afl-fuzz 2>/dev/null)
    
    echo ""
    echo "镜像中Enhanced信息:"
    echo "  时间: $DOCKER_TIME"
    echo "  大小: $(numfmt --to=iec-i --suffix=B $DOCKER_SIZE)"
    echo ""
    echo "本地Enhanced信息:"
    echo "  时间: $ENHANCED_TIME"
    echo "  大小: $(numfmt --to=iec-i --suffix=B $ENHANCED_SIZE)"
    echo ""
    
    if [ "$DOCKER_SIZE" -eq "$ENHANCED_SIZE" ]; then
        echo -e "${GREEN}✓ 大小匹配！镜像已更新${NC}"
    else
        echo -e "${YELLOW}⚠ 大小不匹配，可能需要检查${NC}"
    fi
    
    echo ""
    echo "=========================================="
    echo " 构建完成！"
    echo "=========================================="
    echo ""
    echo "下一步:"
    echo "  1. 快速验证: cd $SCRIPT_DIR && ./verify_fix.sh"
    echo "  2. 完整测试: cd $SCRIPT_DIR && ./compare_fuzzers_docker.sh LightFTP FTP 60"
    echo ""
    
else
    echo ""
    echo -e "${RED}=========================================="
    echo "✗ 构建失败！"
    echo "==========================================${NC}"
    echo ""
    echo "检查日志: cat /tmp/docker_build_full.log"
    exit 1
fi
